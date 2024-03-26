/** @type {import('expo/config').ExpoConfig} */
module.exports = {
  name: "ic-react-native-jwt-auth-app",
  slug: "ic-react-native-jwt-auth-app",
  version: "1.0.0",
  orientation: "portrait",
  icon: "./assets/icon.png",
  userInterfaceStyle: "light",
  plugins: [
    [
      "react-native-auth0",
      {
        domain: process.env.EXPO_PUBLIC_AUTH0_TENANT_DOMAIN,
      },
    ],
  ],
  splash: {
    image: "./assets/splash.png",
    resizeMode: "contain",
    backgroundColor: "#ffffff"
  },
  assetBundlePatterns: [
    "**/*",
  ],
  ios: {
    bundleIdentifier: "io.icp0.jwtauthdemo",
    supportsTablet: true,
  },
  android: {
    package: "io.icp0.jwtauthdemo",
    adaptiveIcon: {
      foregroundImage: "./assets/adaptive-icon.png",
      backgroundColor: "#ffffff",
    },
  },
  web: {
    favicon: "./assets/favicon.png",
  },
  extra: {
    IC_BACKEND_CANISTER_ID: process.env.CANISTER_ID_IC_BACKEND,
    DFX_NETWORK: process.env.DFX_NETWORK,
  },
};
