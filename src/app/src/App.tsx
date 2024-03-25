import { Auth0Provider } from 'react-native-auth0';

import Home from './Home';
import { AUTH0_CLIENT_ID, AUTH0_TENANT_DOMAIN } from './lib/auth0';

const App = () => {
  return (
    <Auth0Provider domain={AUTH0_TENANT_DOMAIN} clientId={AUTH0_CLIENT_ID}>
      <Home />
    </Auth0Provider>
  );
};

export default App;