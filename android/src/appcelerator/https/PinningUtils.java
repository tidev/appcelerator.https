package appcelerator.https;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class PinningUtils {
	/**
	 * Returns returns a list of PinnedHost objects based on a provided host uri
	 * @param host - String representing the host portion of supported Uris
	 * @param supportedHosts - List of PinnedHost information
	 * @return - List of PinnedHost objects
	 */	
	public static List<PinnedHost> getMatchingPinnedHosts(String host, List<PinnedHost> supportedHosts) {
		List<PinnedHost> matches = new ArrayList<PinnedHost>();
		String theHost = (host == null) ? "" : host;
		theHost = theHost.toLowerCase(Locale.ENGLISH).trim();
	
		for(PinnedHost pinnedHost : supportedHosts)  {
			if(theHost.equals(pinnedHost.host.toLowerCase(Locale.ENGLISH).trim())) {
				matches.add(pinnedHost);
			}
		}
		
		return matches;
	}
	/**
	 * Returns if the host is part of the supported configurations.
	 * @param host - String representing the host portion of supported Uris
	 * @param supportedHosts - List of PinnedHost information
	 * @return - True if the host is configured, false otherwise.
	 */
	public static boolean hasMatchingHost(String host, List<PinnedHost> supportedHosts) {
		String theHost = (host == null) ? "" : host;
		theHost = theHost.toLowerCase(Locale.ENGLISH).trim();

		for(PinnedHost pinnedHost : supportedHosts)  {
			if(theHost.equals(pinnedHost.host.toLowerCase(Locale.ENGLISH).trim())) {
				return true;
			}
		}
		return false;
	}
}
