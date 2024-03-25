import { StatusBar } from 'expo-status-bar';
import { useState } from 'react';
import { StyleSheet, Text, View, Button, Alert, Pressable } from 'react-native';
import { type Credentials, useAuth0 } from 'react-native-auth0';
import { fetchApi, type ApiResponse } from './lib/backend';
import { useIcAuth } from './lib/ic';

const Home = () => {
  const { authorize, clearSession, user, error: auth0Error, isLoading: auth0IsLoading } = useAuth0();
  const { baseIdentity, isReady } = useIcAuth();
  const [credentials, setCredentials] = useState<Credentials>();
  const [isLoading, setIsLoading] = useState(false);
  const [apiResponse, setApiResponse] = useState<ApiResponse>();

  const callBackendApi = async (jwt?: string) => {
    setIsLoading(true);
    try {
      const res = await fetchApi(jwt);
      console.log('Backend API response:', res);
      setApiResponse(res);
    } catch (error) {
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  }

  const onLogin = async () => {
    try {
      const credentials = await authorize({
        nonce: baseIdentity?.getPrincipal().toText(),
      });
      console.log('Auth0 credentials:', credentials);
      setCredentials(credentials);

      await callBackendApi(credentials?.idToken);
    } catch (e) {
      console.error(e);
      Alert.alert('Error logging in', (e as Error).message);
    }
  };

  const onLogout = async () => {
    try {
      await clearSession();
      setCredentials(undefined);

      await callBackendApi();
    } catch (e) {
      console.log('Log out cancelled');
    }
  };

  if (auth0IsLoading || isLoading || !isReady) {
    return <View style={styles.container}><Text>Loading...</Text></View>;
  }

  const auth0LoggedIn = user !== undefined && user !== null;

  return (
    <View style={styles.container}>
      <Text style={styles.title}>React Native (Expo) + JWT Authentication + IC Backend demo</Text>

      <Button
        onPress={auth0LoggedIn ? onLogout : onLogin}
        title={auth0LoggedIn ? 'Log Out' : 'Log In'}
      />

      <View style={styles.statusContainer}>
        <Text style={styles.statusTitle}>Auth0 status:</Text>
        {auth0LoggedIn && <Text>You are logged in as {user.name}</Text>}
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
        {auth0Error && <Text style={styles.errorMessage}>{auth0Error.message}</Text>}
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
});

export default Home;
