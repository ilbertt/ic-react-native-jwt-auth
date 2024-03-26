// Inspired by https://github.com/krpeacock/ic-expo-mvp

import Constants from 'expo-constants';
import { Ed25519KeyIdentity } from '@dfinity/identity';
import { ActorSubclass } from '@dfinity/agent';
import { useEffect, useState } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { createActor } from '../declarations';
import { _SERVICE } from '../declarations/ic_backend.did';

const IC_BASE_IDENTITY_STORAGE_KEY = 'ic-base-identity';
const IC_BACKEND_CANISTER_ID = Constants.expoConfig?.extra?.IC_BACKEND_CANISTER_ID;
const DFX_NETWORK = Constants.expoConfig?.extra?.DFX_NETWORK;
process.env.DFX_NETWORK = DFX_NETWORK || 'local';

type IcBackendActor = ActorSubclass<_SERVICE>;

type IcAuth = {
  baseIdentity?: Ed25519KeyIdentity;
  backendActor?: IcBackendActor;
  isReady: boolean;
};

export const useIcAuth = (): IcAuth => {
  const [baseIdentity, setBaseIdentity] = useState<Ed25519KeyIdentity>();
  const [backendActor, setBackendActor] = useState<IcBackendActor>();
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    (async () => {
      let identity: Ed25519KeyIdentity;
      let storedIdentity = await AsyncStorage.getItem(IC_BASE_IDENTITY_STORAGE_KEY);
      if (storedIdentity) {
        identity = Ed25519KeyIdentity.fromJSON(storedIdentity);
      } else {
        identity = Ed25519KeyIdentity.generate();
        await AsyncStorage.setItem(IC_BASE_IDENTITY_STORAGE_KEY, JSON.stringify(identity.toJSON()));
      }
      setBaseIdentity(identity);

      const actor = createActor(IC_BACKEND_CANISTER_ID, {
        agentOptions: {
          identity,
        }
      });
      setBackendActor(actor);

      // TODO: load delegation chain once obtained from the canister

      setIsReady(true);
    })();
  }, []);

  return { baseIdentity, backendActor, isReady };
};
