import Constants from 'expo-constants';

/**
 * The IP of the machine running the Expo Dev server, the backend API and the IC backend.
 */
export const HOST_IP = Constants.expoConfig?.hostUri?.split(':')[0] as string;
