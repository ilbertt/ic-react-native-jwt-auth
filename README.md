# React Native (Expo) app with JWT Authentication and IC Rust canister

## Requirements

- [Bun](https://bun.sh/)
- [Expo's requirements](https://docs.expo.dev/get-started/installation/#requirements) and [local development prerequisites](https://docs.expo.dev/guides/local-app-development/#prerequisites)
- [Rust](https://www.rust-lang.org/)
- [dfx](https://internetcomputer.org/docs/current/developer-docs/getting-started/install/) (preferably installed with the dfx version manager - `dfxvm`)
- an [Auth0](https://auth0.com) account
- an Android/iOS device or simulator

### Configure Auth0

Follow these steps to configure Auth0:

1. [Create a Tenant](https://auth0.com/docs/get-started/auth0-overview/create-tenants) and get your Auth0 Tenant domain, which looks like `<TENANT_NAME>.<TENANT_REGION>.auth0.com`
2. [Create a Native Application](https://auth0.com/docs/get-started/auth0-overview/create-applications/native-apps)
3. In the _Dashboard > Applications > YOUR_APP > Settings_ tab, set the **Allowed Callback URLs** and **Allowed Logout URLs** to:
    - `io.icp0.jwtauthdemo.auth0://<YOUR_AUTH0_TENANT_DOMAIN>/ios/io.icp0.jwtauthdemo/callback`
    - `io.icp0.jwtauthdemo.auth0://<YOUR_AUTH0_TENANT_DOMAIN>/android/io.icp0.jwtauthdemo/callback`

    Where `<YOUR_AUTH0_TENANT_DOMAIN>` is the Auth0 Tenant domain and `io.icp0.jwtauthdemo` is both the **Android Package Name** and **iOS Bundle Identifier**, as configured in the [app.config.js](./src/app/app.config.js) file.
4. In the _Dashboard > Applications > YOUR_APP > Credentials_ tab, set the **Authentication Method** to **None** (instead of **Client Secret (Post)**)

The 1st step of the Auth0 React Native [Quickstart interactive guide](https://auth0.com/docs/quickstart/native/react-native-expo/interactive) can be helpful too.

## Usage

Install the `wasm32-unknown-unknown` target in the Rust toolchain:

```bash
rustup target add wasm32-unknown-unknown
```

Install the dependencies:

```bash
bun install
```

Copy the [`.env.example`](./.env.example) file to `.env`:

```bash
cp .env.example .env
```
and replace the values with your own.

Start the IC backend:

```bash
# in a separate terminal
bun start:dfx
# in the main terminal
bun deploy:ic_backend
```

Start the off-chain backend:

```bash
bun start:app_backend
```

Start the mobile app, run:

```bash
# Android
bun start:android
# iOS
bun start:ios
```
See the `expo start` CLI [docs](https://docs.expo.dev/more/expo-cli/#develop) for more information.
