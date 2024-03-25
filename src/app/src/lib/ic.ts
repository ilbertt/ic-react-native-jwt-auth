// Inspired by https://github.com/krpeacock/ic-expo-mvp

import { Ed25519KeyIdentity } from '@dfinity/identity';
import { useEffect, useState } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';

const IC_BASE_IDENTITY_STORAGE_KEY = 'ic-base-identity';

type IcAuth = {
  baseIdentity?: Ed25519KeyIdentity;
  isReady: boolean;
};

export const useIcAuth = (): IcAuth => {
  const [baseIdentity, setBaseIdentity] = useState<Ed25519KeyIdentity>();
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    (async () => {
      const storedIdentity = await AsyncStorage.getItem(IC_BASE_IDENTITY_STORAGE_KEY);
      if (storedIdentity) {
        setBaseIdentity(Ed25519KeyIdentity.fromJSON(storedIdentity));
      } else {
        const identity = Ed25519KeyIdentity.generate();
        setBaseIdentity(identity);
        await AsyncStorage.setItem(IC_BASE_IDENTITY_STORAGE_KEY, JSON.stringify(identity.toJSON()));
      }

      // TODO: load delegation chain once obtained from the canister

      setIsReady(true);
    })();
  }, []);

  return { baseIdentity, isReady };
};
