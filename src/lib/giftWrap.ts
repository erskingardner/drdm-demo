import NDK, { NDKEvent } from "@nostr-dev-kit/ndk";
import { NDKPrivateKeySigner } from "@nostr-dev-kit/ndk";
import { nip44 } from "nostr-tools";

/**
 * Wraps a rumor event in a seal and a gift wrap event.
 * @param ndk - The NDK instance.
 * @param rumor - The NDKEvent to wrap.
 * @param recipientPubkey - The public key of the recipient.
 * @param signer - The NDK private key signer.
 * @returns A promise that resolves to the wrapped gift wrap event. Signed and ready to be published.
 */
export async function giftWrap(
    ndk: NDK,
    rumor: NDKEvent,
    recipientPubkey: string,
    signer: NDKPrivateKeySigner
): Promise<NDKEvent> {
    const rumorConversationKey = nip44.v2.utils.getConversationKey(
        signer.privateKey!,
        recipientPubkey
    );
    const encryptedRumor = nip44.v2.encrypt(JSON.stringify(rumor), rumorConversationKey);

    const sealEvent = new NDKEvent(ndk, {
        kind: 13,
        created_at: Math.floor(Date.now() / 1000),
        pubkey: rumor.pubkey,
        content: encryptedRumor,
        tags: []
    });
    await sealEvent.sign(signer);

    const gwSigner = NDKPrivateKeySigner.generate();
    const gwPubkey = (await gwSigner.user()).pubkey;

    const sealConversationKey = nip44.v2.utils.getConversationKey(
        gwSigner.privateKey!,
        recipientPubkey
    );
    const encryptedSeal = nip44.v2.encrypt(JSON.stringify(sealEvent), sealConversationKey);

    const wrapEvent = new NDKEvent(ndk, {
        kind: 1059,
        created_at: Math.floor(Date.now() / 1000),
        pubkey: gwPubkey,
        content: encryptedSeal,
        tags: [["p", recipientPubkey]]
    });

    await wrapEvent.sign(gwSigner);
    return wrapEvent;
}

export function unwrap(ndk: NDK, event: NDKEvent, recipientSigner: NDKPrivateKeySigner): NDKEvent {
    const gwConversationKey = nip44.v2.utils.getConversationKey(
        recipientSigner.privateKey!,
        event.pubkey
    );
    const gwContent = nip44.v2.decrypt(event.content, gwConversationKey);
    const sealEvent = new NDKEvent(ndk, JSON.parse(gwContent));
    const sealConversationKey = nip44.v2.utils.getConversationKey(
        recipientSigner.privateKey!,
        sealEvent.pubkey
    );
    const rumorContent = nip44.v2.decrypt(sealEvent.content, sealConversationKey);
    const rumor = new NDKEvent(ndk, JSON.parse(rumorContent));

    return rumor;
}
