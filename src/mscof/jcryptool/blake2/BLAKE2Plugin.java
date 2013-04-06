package mscof.jcryptool.blake2;

import org.eclipse.ui.plugin.AbstractUIPlugin;
import org.osgi.framework.BundleContext;

/**
 * The activator class controls the plug-in life cycle
 */
public class BLAKE2Plugin extends AbstractUIPlugin {

	// The plug-in ID
	public static final String PLUGIN_ID = "mscof.jcryptool.blake2"; //$NON-NLS-1$

	// The shared instance
	private static BLAKE2Plugin plugin;
	
	/**
	 * The constructor
	 */
	public BLAKE2Plugin() {
	}

	/*
	 * (non-Javadoc)
	 * @see org.eclipse.ui.plugin.AbstractUIPlugin#start(org.osgi.framework.BundleContext)
	 */
	public void start(BundleContext context) throws Exception {
		super.start(context);
		plugin = this;
	}

	/*
	 * (non-Javadoc)
	 * @see org.eclipse.ui.plugin.AbstractUIPlugin#stop(org.osgi.framework.BundleContext)
	 */
	public void stop(BundleContext context) throws Exception {
		plugin = null;
		super.stop(context);
	}

	/**
	 * Returns the shared instance
	 *
	 * @return the shared instance
	 */
	public static BLAKE2Plugin getDefault() {
		return plugin;
	}

}
