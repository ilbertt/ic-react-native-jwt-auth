// polyfills
import { polyfill as polyfillEncoding } from 'react-native-polyfill-globals/src/encoding';
import { polyfill as polyfillCrypto } from 'react-native-polyfill-globals/src/crypto';
polyfillEncoding();
polyfillCrypto();
globalThis.TextEncoder = TextEncoder;
window.TextEncoder = TextEncoder;
import { TextEncoder } from 'text-encoding';
import 'react-native-get-random-values';

import { registerRootComponent } from 'expo';

import App from './src/App';

// registerRootComponent calls AppRegistry.registerComponent('main', () => App);
// It also ensures that whether you load the app in Expo Go or in a native build,
// the environment is set up appropriately
registerRootComponent(App);
