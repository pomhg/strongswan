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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class NetworkManager extends BroadcastReceiver implements Runnable
{
	/* delay notifications until the callbacks that usually follow a change arrived */
	private static final long NETWORK_CHANGE_DELAY_MS = 300;
	private static final int NETWORK_UNUSABLE = -1;

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
	private LinkProperties mSelectedLinkProperties;
	private boolean mEventPending;
	private boolean mConnected;
	private long mEventDeadline;

	public NetworkManager(Context context)
	{
		mContext = context;

		/* only Android 8+ guarantees that onCapabilitiesChanged() and
		 * onLinkPropertiesChanged() are called after onAvailable() */
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
		{
			mCallback = new ConnectivityManager.NetworkCallback()
			{
				@Override
				public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities)
				{
					synchronized (NetworkManager.this)
					{
						getNetworkState(network).capabilities = capabilities;
						updateSelectedNetwork();
					}
				}

				@Override
				public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties)
				{
					synchronized (NetworkManager.this)
					{
						getNetworkState(network).linkProperties = linkProperties;
						updateSelectedNetwork();
					}
				}

				@Override
				public void onBlockedStatusChanged(Network network, boolean blocked)
				{
					/* only called on Android 10+ */
					synchronized (NetworkManager.this)
					{
						getNetworkState(network).blocked = blocked;
						updateSelectedNetwork();
					}
				}

				@Override
				public void onLost(Network network)
				{
					synchronized (NetworkManager.this)
					{
						mNetworks.remove(network);
						updateSelectedNetwork();
					}
				}
			};
		}
	}

	/**
	 * Get or create the state of the given network, lock has to be held.
	 */
	private NetworkState getNetworkState(Network network)
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
	 * Score a network, higher is better.  Validated networks are preferred
	 * over unvalidated ones, Ethernet/Wi-Fi over others and unmetered over
	 * metered networks.
	 */
	private static int getNetworkScore(NetworkState state)
	{
		NetworkCapabilities caps = state.capabilities;
		LinkProperties props = state.linkProperties;

		if (caps == null || props == null || state.blocked ||
			props.getLinkAddresses().isEmpty() || !hasDefaultRoute(props) ||
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

	private static boolean hasDefaultRoute(LinkProperties props)
	{
		for (RouteInfo route : props.getRoutes())
		{
			if (route.isDefaultRoute())
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * Select the best usable network and queue an event if the selected network
	 * or its addresses/routes changed, lock has to be held.  The currently
	 * selected network is kept if another network has the same score.
	 */
	private void updateSelectedNetwork()
	{
		Network selected = null;
		int best = NETWORK_UNUSABLE;

		NetworkState current = mSelectedNetwork != null ? mNetworks.get(mSelectedNetwork) : null;
		if (current != null)
		{
			selected = mSelectedNetwork;
			best = getNetworkScore(current);
		}
		for (Map.Entry<Network, NetworkState> entry : mNetworks.entrySet())
		{
			int score = getNetworkScore(entry.getValue());
			if (score > best)
			{
				selected = entry.getKey();
				best = score;
			}
		}
		if (best == NETWORK_UNUSABLE)
		{
			selected = null;
		}
		LinkProperties props = selected != null ? mNetworks.get(selected).linkProperties : null;

		if (!Objects.equals(selected, mSelectedNetwork) ||
			!sameAddressesAndRoutes(props, mSelectedLinkProperties))
		{
			mSelectedNetwork = selected;
			mSelectedLinkProperties = props;
			queueNetworkChange(selected != null);
		}
	}

	private static boolean sameAddressesAndRoutes(LinkProperties a, LinkProperties b)
	{
		if (a == null || b == null)
		{
			return a == b;
		}
		return a.getLinkAddresses().equals(b.getLinkAddresses()) &&
			   a.getRoutes().equals(b.getRoutes());
	}

	/**
	 * Queue a delayed event for the native parts, lock has to be held.  The
	 * delay is restarted with every update so the native parts only see the
	 * final state after a burst of changes.
	 */
	private void queueNetworkChange(boolean connected)
	{
		mConnected = connected;
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
			mSelectedLinkProperties = null;
			mEventPending = false;
			mRegistered = true;
		}
		mEventNotifier = new Thread(this);
		mEventNotifier.start();
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
		{
			ConnectivityManager cm = mContext.getSystemService(ConnectivityManager.class);
			/* the app's default network is the VPN itself, so we listen for all
			 * non-VPN networks with Internet access and select one ourselves */
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
			notifyAll();
		}
		try
		{
			mEventNotifier.join();
			mEventNotifier = null;
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();
		}
		synchronized (this)
		{
			mNetworks.clear();
			mSelectedNetwork = null;
			mSelectedLinkProperties = null;
		}
		/* revert to the default behavior of following the default network */
		setUnderlyingNetworks(null);
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
	 * Bind the given (unconnected) socket to the currently selected network.
	 * Sockets are rebound when the native parts protect them again after a
	 * network change.
	 *
	 * @param fd native socket
	 * @return false if binding the socket failed
	 */
	public boolean bindSocket(int fd)
	{
		Network network;

		synchronized (this)
		{
			network = mSelectedNetwork;
		}
		if (network == null)
		{	/* only selected via NetworkCallback on Android 8+ */
			return true;
		}
		/* fromFd() duplicates the file descriptor, closing it doesn't close the socket */
		try (ParcelFileDescriptor pfd = ParcelFileDescriptor.fromFd(fd))
		{
			network.bindSocket(pfd.getFileDescriptor());
			return true;
		}
		catch (IOException e)
		{
			return false;
		}
	}

	/**
	 * Let the system know which network the VPN actually uses (e.g. to report
	 * whether it's metered), otherwise, the system default network is assumed.
	 */
	private void setUnderlyingNetworks(Network[] networks)
	{
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && mContext instanceof VpnService)
		{
			/* this fails if the VPN is not established, CharonVpnService
			 * applies the networks when it creates the TUN device */
			((VpnService)mContext).setUnderlyingNetworks(networks);
		}
	}

	@Override
	public void onReceive(Context context, Intent intent)
	{
		synchronized (this)
		{
			queueNetworkChange(isConnected());
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
					while (mRegistered)
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
					break;
				}
				if (!mRegistered)
				{
					break;
				}
				connected = mConnected;
				network = mSelectedNetwork;
				mEventPending = false;
			}
			/* call the native parts without holding the lock */
			setUnderlyingNetworks(network != null ? new Network[]{network} : new Network[0]);
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
