/*
 * Copyright (C) 2012-2019 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

package org.strongswan.android.logic;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.util.Log;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class NetworkManager extends BroadcastReceiver implements Runnable
{
	private static final String TAG = NetworkManager.class.getSimpleName();
	/* Wait for the capabilities/link properties callbacks that follow onAvailable(). */
	private static final long NETWORK_CHANGE_DELAY_MS = 300;
	private static final int NETWORK_UNUSABLE = Integer.MIN_VALUE;

	private static class NetworkState
	{
		NetworkCapabilities capabilities;
		LinkProperties linkProperties;
		boolean blocked;
	}

	private final Context mContext;
	private volatile boolean mRegistered;
	private ConnectivityManager.NetworkCallback mCallback;
	private Thread mEventNotifier;
	private final Map<Network, NetworkState> mNetworks = new HashMap<>();
	private Network mSelectedNetwork;
	private boolean mEventPending;
	private boolean mPendingConnected;
	private long mEventDeadline;

	public NetworkManager(Context context)
	{
		mContext = context;
		/* Only Android 8+ guarantees initial capabilities and link properties
		 * callbacks after onAvailable().  Older versions use the receiver. */

		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
		{
			mCallback = new ConnectivityManager.NetworkCallback()
			{
				@Override
				public void onAvailable(Network network)
				{
					synchronized (NetworkManager.this)
					{
						if (!mNetworks.containsKey(network))
						{
							mNetworks.put(network, new NetworkState());
						}
					}
				}

				@Override
				public void onCapabilitiesChanged(Network network,
											  NetworkCapabilities capabilities)
				{
					synchronized (NetworkManager.this)
					{
						NetworkState state = getNetworkStateLocked(network);
						boolean selected = network.equals(mSelectedNetwork);
						int oldSignature = selected ? getNetworkSignature(state) : 0;

						state.capabilities = capabilities;
						selectionUpdatedLocked(network, selected, oldSignature);
					}
				}

				@Override
				public void onLinkPropertiesChanged(Network network,
											 LinkProperties linkProperties)
				{
					synchronized (NetworkManager.this)
					{
						NetworkState state = getNetworkStateLocked(network);
						boolean selected = network.equals(mSelectedNetwork);
						int oldSignature = selected ? getNetworkSignature(state) : 0;

						state.linkProperties = linkProperties;
						selectionUpdatedLocked(network, selected, oldSignature);
					}
				}

				@Override
				public void onLost(Network network)
				{
					synchronized (NetworkManager.this)
					{
						mNetworks.remove(network);
						if (selectNetworkLocked())
						{
							queueNetworkChangeLocked();
						}
					}
				}

				@Override
				public void onBlockedStatusChanged(Network network, boolean blocked)
				{
					if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
					{
						synchronized (NetworkManager.this)
						{
							NetworkState state = getNetworkStateLocked(network);
							boolean selected = network.equals(mSelectedNetwork);
							int oldSignature = selected ? getNetworkSignature(state) : 0;

							state.blocked = blocked;
							selectionUpdatedLocked(network, selected, oldSignature);
						}
					}
				}
			};
		}
	}

	/**
	 * Get or create state for a network.  The caller must hold this object's lock.
	 */
	private NetworkState getNetworkStateLocked(Network network)
	{
		NetworkState state = mNetworks.get(network);
		if (state == null)
		{
			state = new NetworkState();
			mNetworks.put(network, state);
		}
		return state;
	}

	/**
	 * Return whether the link has an address and a usable default route.
	 */
	private static boolean hasUsableLink(NetworkState state)
	{
		if (state.linkProperties == null || state.linkProperties.getLinkAddresses().isEmpty())
		{
			return false;
		}
		for (RouteInfo route : state.linkProperties.getRoutes())
		{
			if (route.isDefaultRoute())
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * Score a non-VPN Internet network.  Validated, unmetered Wi-Fi/Ethernet
	 * networks are preferred, while the current network wins equal scores.
	 */
	private static int getNetworkScore(NetworkState state)
	{
		if (state == null)
		{
			return NETWORK_UNUSABLE;
		}
		NetworkCapabilities caps = state.capabilities;
		if (caps == null || state.blocked || !hasUsableLink(state) ||
			!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
			!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
			(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
			 !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)))
		{
			return NETWORK_UNUSABLE;
		}

		int score = 0;
		if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
		{
			score += 100;
		}
		if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
		{
			score += 30;
		}
		else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
		{
			score += 20;
		}
		if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
		{
			score += 10;
		}
		return score;
	}

	/**
	 * Hash only properties that affect source-address and route selection.
	 */
	private static int getNetworkSignature(NetworkState state)
	{
		int hash = getNetworkScore(state);
		if (state.linkProperties != null)
		{
			hash = 31 * hash + state.linkProperties.getLinkAddresses().hashCode();
			hash = 31 * hash + state.linkProperties.getRoutes().hashCode();
		}
		return hash;
	}

	/**
	 * Recalculate the selected network after a callback updated its state.
	 */
	private void selectionUpdatedLocked(Network network, boolean wasSelected,
										int oldSignature)
	{
		boolean changed = selectNetworkLocked();
		if (changed || (wasSelected && network.equals(mSelectedNetwork) &&
			oldSignature != getNetworkSignature(mNetworks.get(network))))
		{
			queueNetworkChangeLocked();
		}
	}

	/**
	 * Select the best currently usable network.  The current network is used as
	 * the initial candidate so equal scores don't cause unnecessary roaming.
	 *
	 * @return true if the selected network changed
	 */
	private boolean selectNetworkLocked()
	{
		Network previous = mSelectedNetwork;
		Network selected = previous;
		int bestScore = getNetworkScore(mNetworks.get(selected));

		for (Map.Entry<Network, NetworkState> entry : mNetworks.entrySet())
		{
			int score = getNetworkScore(entry.getValue());
			if (score > bestScore)
			{
				selected = entry.getKey();
				bestScore = score;
			}
		}
		if (bestScore == NETWORK_UNUSABLE)
		{
			selected = null;
		}
		mSelectedNetwork = selected;

		boolean changed = previous == null ? selected != null : !previous.equals(selected);
		if (changed)
		{
			Log.i(TAG, "selected underlying network changed from " + previous + " to " + selected);
		}
		return changed;
	}

	/**
	 * Queue a debounced native connectivity event.  Each update moves the
	 * deadline so the native route lookup sees the final capabilities and routes.
	 */
	private void queueNetworkChangeLocked()
	{
		if (!mRegistered)
		{
			return;
		}
		mPendingConnected = mSelectedNetwork != null;
		mEventDeadline = SystemClock.elapsedRealtime() + NETWORK_CHANGE_DELAY_MS;
		mEventPending = true;
		notifyAll();
	}

	public void Register()
	{
		synchronized (this)
		{
			mNetworks.clear();
			mSelectedNetwork = null;
			mEventPending = false;
			mRegistered = true;
		}
		mEventNotifier = new Thread(this, "strongSwan network events");
		mEventNotifier.start();
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
		{
			ConnectivityManager cm = mContext.getSystemService(ConnectivityManager.class);
			/* The app's default network is the VPN itself, so listen for all
			 * Internet-capable non-VPN networks and select the best one ourselves. */
			NetworkRequest.Builder builder = new NetworkRequest.Builder()
				.addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
				.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
			cm.registerNetworkCallback(builder.build(), mCallback);
		}
		else
		{
			registerLegacyReceiver();
		}
	}

	@SuppressWarnings("deprecation")
	private void registerLegacyReceiver()
	{
		/* deprecated since API level 28 */
		mContext.registerReceiver(this, new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION));
	}

	public void Unregister()
	{
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
		{
			ConnectivityManager cm = mContext.getSystemService(ConnectivityManager.class);
			cm.unregisterNetworkCallback(mCallback);
		}
		else
		{
			mContext.unregisterReceiver(this);
		}
		synchronized (this)
		{
			mRegistered = false;
			mEventPending = false;
			mNetworks.clear();
			mSelectedNetwork = null;
			notifyAll();
		}
		try
		{
			mEventNotifier.join();
			mEventNotifier = null;
		}
		catch (InterruptedException e)
		{
			Thread.currentThread().interrupt();
		}
	}

	@SuppressWarnings("deprecation")
	public boolean isConnected()
	{
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
		{
			synchronized (this)
			{
				return mSelectedNetwork != null;
			}
		}
		/* deprecated since API level 29 */
		ConnectivityManager cm = (ConnectivityManager)mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
		android.net.NetworkInfo info = null;
		if (cm != null)
		{
			info = cm.getActiveNetworkInfo();
		}
		return info != null && info.isConnected();
	}

	/**
	 * Bind an unconnected native socket to the currently selected underlying
	 * Android network.  fromFd() duplicates the descriptor, so closing the
	 * ParcelFileDescriptor does not close the native socket.
	 *
	 * @param fd native socket descriptor
	 * @return true if the socket was bound to a selected network
	 */
	public boolean bindSocket(int fd)
	{
		Network network;
		synchronized (this)
		{
			network = mSelectedNetwork;
		}
		if (network == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
		{
			return false;
		}
		try (ParcelFileDescriptor pfd = ParcelFileDescriptor.fromFd(fd))
		{
			network.bindSocket(pfd.getFileDescriptor());
			return true;
		}
		catch (IOException | RuntimeException e)
		{
			Log.w(TAG, "failed to bind socket to network " + network, e);
			return false;
		}
	}

	/**
	 * Tell Android which physical network carries the explicitly-bound tunnel
	 * sockets.  Without this, the VPN remains associated with the system default
	 * network, which may still be the old network during a handover.
	 */
	private void setUnderlyingNetwork(Network network)
	{
		/* Only the NetworkCallback path selects and explicitly binds an
		 * underlying Network.  Legacy versions continue to use the default. */
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
			!(mContext instanceof VpnService))
		{
			return;
		}
		Network[] networks = network == null ? new Network[0] : new Network[] { network };
		if (!((VpnService)mContext).setUnderlyingNetworks(networks))
		{
			/* This may fail before the VPN is established.  CharonVpnService
			 * retains the selection and applies it when creating the interface. */
			Log.w(TAG, "failed to set VPN underlying network to " + network);
		}
	}

	@Override
	public void onReceive(Context context, Intent intent)
	{
		synchronized (this)
		{
			mPendingConnected = isConnected();
			mEventDeadline = SystemClock.elapsedRealtime() + NETWORK_CHANGE_DELAY_MS;
			mEventPending = true;
			notifyAll();
		}
	}

	@Override
	public void run()
	{
		while (true)
		{
			boolean connected;
			Network network;

			synchronized (this)
			{
				try
				{
					while (mRegistered && !mEventPending)
					{
						wait();
					}
					while (mRegistered && mEventPending)
					{
						long delay = mEventDeadline - SystemClock.elapsedRealtime();
						if (delay <= 0)
						{
							break;
						}
						wait(delay);
					}
				}
				catch (InterruptedException ex)
				{
					Thread.currentThread().interrupt();
					break;
				}
				if (!mRegistered)
				{
					break;
				}
				connected = mPendingConnected;
				network = mSelectedNetwork;
				mEventPending = false;
			}
			/* Keep the VPN's declared upstream synchronized with the network used
			 * for native sockets, then call native code without holding the lock. */
			setUnderlyingNetwork(network);
			networkChanged(!connected);
		}
	}

	/**
	 * Notify the native parts about a network change
	 *
	 * @param disconnected true if no connection is available at the moment
	 */
	public native void networkChanged(boolean disconnected);
}
