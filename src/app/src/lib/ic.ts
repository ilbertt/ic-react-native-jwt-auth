// Inspired by https://github.com/krpeacock/ic-expo-mvp

import Constants from 'expo-constants';
import {
  Delegation,
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
  type SignedDelegation,
  isDelegationValid,
} from '@dfinity/identity';
import { ActorSubclass, SignIdentity, Signature } from '@dfinity/agent';
import { useEffect, useState } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { createActor } from '../declarations';
import { type _SERVICE } from '../declarations/ic_backend.did';
import { HOST_IP } from './common';

const IC_IDENTITY_STORAGE_KEY = 'ic-identity-delegation';
const IC_BACKEND_CANISTER_ID = Constants.expoConfig?.extra?.IC_BACKEND_CANISTER_ID;
const DFX_NETWORK = Constants.expoConfig?.extra?.DFX_NETWORK;
process.env.DFX_NETWORK = DFX_NETWORK || 'local';

type IcBackendActor = ActorSubclass<_SERVICE>;

export const createIcBackendActor = (identity: SignIdentity): IcBackendActor => {
  return createActor(IC_BACKEND_CANISTER_ID, {
    agentOptions: {
      identity,
      host: DFX_NETWORK === 'local' ? `http://${HOST_IP}:4943` : 'https://icp-api.io',
      fetchOptions: {
        reactNative: {
          __nativeResponseType: "base64",
        },
      },
      verifyQuerySignatures: true,
      callOptions: {
        reactNative: {
          textStreaming: true,
        },
      },
    }
  });
}

type IcAuth = {
  sessionIdentity?: Ed25519KeyIdentity;
  delegationIdentity?: DelegationIdentity;
  login: (idToken: string) => Promise<DelegationIdentity>;
  logout: () => Promise<void>;
  isLoggedIn: () => boolean;
};

export const useIcAuth = (): IcAuth => {
  const [sessionIdentity, setSessionIdentity] = useState<Ed25519KeyIdentity>();
  const [delegationIdentity, setDelegationIdentity] = useState<DelegationIdentity>();

  const login = async (idToken: string): Promise<DelegationIdentity> => {
    if (!sessionIdentity) {
      throw new Error('No session identity');
    }

    const sessionActor = createIcBackendActor(sessionIdentity);

    const { user_key, expiration } = await sessionActor.prepare_delegation(idToken);
    const delegationRes = await sessionActor.get_delegation(idToken, expiration);

    if ('no_such_delegation' in delegationRes) {
      throw new Error('No delegation from canister');
    }

    const signedDelegation = delegationRes.signed_delegation;
    const delegation: SignedDelegation = {
      delegation: new Delegation(
        Uint8Array.from(signedDelegation.delegation.pubkey).buffer as ArrayBuffer,
        BigInt(signedDelegation.delegation.expiration),
        undefined,
      ),
      signature: Uint8Array.from(
        signedDelegation.signature
      ) as unknown as Signature,
    };

    const delegationChain = DelegationChain.fromDelegations(
      [delegation],
      Uint8Array.from(user_key).buffer as ArrayBuffer,
    );

    const identity = DelegationIdentity.fromDelegation(
      sessionIdentity,
      delegationChain
    );
    setDelegationIdentity(identity);

    return identity;
  };

  const logout = async () => {
    setDelegationIdentity(undefined);
    await AsyncStorage.removeItem(IC_IDENTITY_STORAGE_KEY);
  };

  const isLoggedIn = () => !!delegationIdentity;

  useEffect(() => {
    (async () => {
      const sessionId = Ed25519KeyIdentity.generate();
      const storedDelegation = await AsyncStorage.getItem(IC_IDENTITY_STORAGE_KEY);
      if (storedDelegation) {
        const chain = DelegationChain.fromJSON(JSON.parse(storedDelegation));
        if (isDelegationValid(chain)) {
          const id = DelegationIdentity.fromDelegation(
            sessionId,
            chain,
          );
          setDelegationIdentity(id);
        } else {
          await AsyncStorage.removeItem(IC_IDENTITY_STORAGE_KEY);
        }
      }

      setSessionIdentity(sessionId);
    })();
  }, []);

  return {
    sessionIdentity,
    delegationIdentity,
    login,
    logout,
    isLoggedIn,
  };
};
