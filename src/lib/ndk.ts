import NDK from "@nostr-dev-kit/ndk";
import { writable } from "svelte/store";

export const ndkStore = new NDK({
    explicitRelayUrls: [
        "ws://localhost:8000"
        // 'wss://purplepag.es',
        // 'wss://relay.nostr.band',
        // 'wss://nos.lol',
        // 'wss://relay.snort.social',
        // 'wss://relay.damus.io',
        // 'wss://relay.primal.net'
    ],
    outboxRelayUrls: ["ws://localhost:8000"],
    enableOutboxModel: false,
    autoFetchUserMutelist: false,
    autoConnectUserRelays: false
});

ndkStore
    .connect()
    .then(() => console.log("NDK Connected"))
    .catch((e) => console.error("NDK Connection Error", e));

// Create a singleton instance that is the default export
const ndk = writable(ndkStore);

export default ndk;
