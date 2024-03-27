import { StatusBar } from 'expo-status-bar';
import { useState } from 'react';
import { StyleSheet, Text, View, Button, Alert, Pressable } from 'react-native';
import { type Credentials, useAuth0 } from 'react-native-auth0';
import { Principal } from '@dfinity/principal';
import { toHex } from '@dfinity/agent';
import { fetchApi, type ApiResponse } from './lib/backend';
import { createIcBackendActor, useIcAuth } from './lib/ic';
import { DelegationIdentity } from '@dfinity/identity';
import { type AuthenticatedResponse } from './declarations/ic_backend.did';

const Home = () => {
  const { authorize, clearSession, user, error: auth0Error, isLoading: auth0IsLoading } = useAuth0();
  const { sessionIdentity, delegationIdentity, login, logout } = useIcAuth();
  const [credentials, setCredentials] = useState<Credentials>();
  const [isLoading, setIsLoading] = useState(false);
  const [apiResponse, setApiResponse] = useState<ApiResponse>();
  const [canisterResponse, setCanisterResponse] = useState<AuthenticatedResponse>();

  const callBackendApi = async (jwt?: string) => {
    setIsLoading(true);
    try {
      if (!sessionIdentity) {
        throw new Error('No session identity');
      }

      const res = await fetchApi(jwt);
      console.log('Backend API response:', res);

      if (res.status === 200 && res.data) {
        if (Principal.fromText(res.data.session_principal).compareTo(sessionIdentity.getPrincipal()) !== 'eq') {
          throw new Error('Principal mismatch');
        }
      }

      setApiResponse(res);
    } catch (error) {
      console.error(error);
    }

    setIsLoading(false);
  };

  const callCanister = async (jwt?: string, identity?: DelegationIdentity) => {
    setIsLoading(true);
    try {
      if (!identity) {
        throw new Error('No delegation identity');
      }

      if (!jwt) {
        throw new Error('No jwt');
      }

      const actor = createIcBackendActor(identity);
      const res = await actor.authenticated();
      console.log('Canister response:', res);
      console.log('Delegation principal:', identity.getPrincipal().toText());
      setCanisterResponse(res);
    } catch (e) {
      console.error(e);
    }

    setIsLoading(false);
  };

  const onLogin = async () => {
    try {
      if (!sessionIdentity) {
        throw new Error('No base identity');
      }

      const res = await authorize({
        nonce: toHex(sessionIdentity.getPublicKey().toDer()),
      });

      if (!res || !res.idToken) {
        throw new Error('Auth0 response is empty or missing idToken');
      }

      console.log('Auth0 credentials:', res);
      setCredentials(res);

      setIsLoading(true);
      const identity = await login(res.idToken);
      setIsLoading(false);

      await callCanister(res.idToken, identity);

      await callBackendApi(res.idToken);
    } catch (e) {
      console.error(e);
      Alert.alert('Error logging in', (e as Error).message);
    }
  };

  const onLogout = async () => {
    try {
      await clearSession();
      setCredentials(undefined);

      await logout();

      setCanisterResponse(undefined);

      await callBackendApi();
    } catch (e) {
      console.log('Log out cancelled');
    }
  };

  if (auth0IsLoading || isLoading || !sessionIdentity) {
    return <View style={styles.container}><Text>Loading...</Text></View>;
  }

  const auth0LoggedIn = credentials && credentials.idToken && user;

  return (
    <View style={styles.container}>
      <Text style={styles.title}>React Native (Expo) + JWT Authentication + IC Backend demo</Text>

      <Button
        onPress={auth0LoggedIn ? onLogout : onLogin}
        title={auth0LoggedIn ? 'Log Out' : 'Log In'}
      />

      <View style={styles.statusContainer}>
        <Text style={styles.statusTitle}>Auth0 status:</Text>
        {auth0LoggedIn && <Text>Logged in with sub: <Text style={styles.subText}>{user.sub}</Text></Text>}
        {!auth0LoggedIn && <Text>You are not logged in</Text>}
        {auth0Error && <Text style={styles.errorMessage}>{auth0Error.message}</Text>}
      </View>

      <View style={styles.statusContainer}>
        <Text style={styles.statusTitle}>Backend API status:</Text>
        {(!apiResponse || apiResponse.status !== 200) && <Text>You are not authenticated</Text>}
        {(apiResponse && apiResponse!.status === 200) && <Text>You are authenticated!</Text>}
        <Pressable
          onPress={() => callBackendApi(credentials?.idToken)}
        >
          <Text style={styles.statusButtonText}>Refresh</Text>
        </Pressable>
      </View>

      <View style={styles.statusContainer}>
        <Text style={styles.statusTitle}>IC Backend status:</Text>
        {(!canisterResponse) && <Text>You are not logged in</Text>}
        {(canisterResponse) && <Text>Logged in with sub: <Text style={styles.subText}>{canisterResponse.user_sub}</Text></Text>}
        <Pressable
          onPress={() => callCanister(credentials?.idToken, delegationIdentity)}
        >
          <Text style={styles.statusButtonText}>Refresh</Text>
        </Pressable>
      </View>

      <StatusBar style="auto" />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    gap: 30,
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  title: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  statusContainer: {
    flexDirection: 'column',
    justifyContent: 'center',
    alignItems: 'center',
    gap: 10,
  },
  statusTitle: {
    fontSize: 16,
    textAlign: 'center',
    margin: 10,
    fontWeight: 'bold',
  },
  statusButtonText: {
    fontSize: 12,
    color: 'blue',
  },
  errorMessage: {
    color: 'red',
  },
  subText: {
    fontWeight: 'bold',
  }
});

export default Home;
