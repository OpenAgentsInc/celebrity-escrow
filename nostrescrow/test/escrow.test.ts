import {generatePrivateKey, getPublicKey, nip19} from "nostr-tools"

Object.assign(global, { WebSocket: require('ws') });
Object.assign(global, { crypto: require('crypto') });

import {NostrEscrow} from "../src"
import exp from "constants";

const maker_priv = generatePrivateKey();
const maker_nsec = nip19.nsecEncode(maker_priv);
const taker_priv = generatePrivateKey();
const taker_nsec = nip19.nsecEncode(taker_priv);
const taker_pub = getPublicKey(taker_priv)
const escrow_priv = generatePrivateKey();
const escrow_nsec = nip19.nsecEncode(escrow_priv);
const escrow_pub = getPublicKey(escrow_priv)

describe("NostrEscrow", () => {
    const n = new NostrEscrow()

    n.setRelays(["wss://relay.taxi"])
    it("can create a contract", async () => {
        const event = await n.createContract({
          maker_nsec: maker_nsec,
          taker_pub: taker_pub,
          escrow_pub: taker_pub,
          maker_sats: 10,
          taker_sats: 10,
          escrow_sats: 0,
          maker_sig: "sig",
          contract_text: "con",
        });
        expect(event).toBeTruthy()
        const contract2 = await n.getContract("taker", taker_nsec, event.id)
        expect(contract2.contract_text).toBe("con")
        expect(contract2.shared_secret).toBeTruthy()
        const accept_event = await n.acceptContract({
            taker_nsec: taker_nsec,
            taker_sig: ["sig", "sig2"],
            maker_pub: event.pubkey,
            event_id: event.id,
            contract_hash: contract2.contract_hash
        })
        expect(accept_event).toBeTruthy()
        const contract3 = await n.getContract("maker", maker_nsec, event.id)
        expect(contract3.contract_text).toBe("con")
        expect(contract3.taker_sig).toBeTruthy()
        const contract4 = await n.getContract("escrow", contract2.shared_secret, event.id)
        expect(contract4.contract_text).toBe("con")
        expect(contract4.taker_sig).toBeTruthy()
    })

    it("can tweak stuff", async () => {
         const event = await n.createContractEvent({
          maker_nsec: maker_nsec,
          taker_pub: taker_pub,
          escrow_pub: taker_pub,
          maker_sats: 10,
          taker_sats: 10,
          escrow_sats: 0,
          maker_sig: "sig",
          contract_text: "con",
        });
        const contract_hash = await n.getHashFromEvent(event)
        const shared_secret = await n.getContractSharedSecret(taker_priv, event.pubkey, contract_hash)
        const decrypt_works = await n.decryptWithSharedSecret(shared_secret, event.content)
        console.log(decrypt_works)
    })
})
