import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";
import {
  exportPrvKey,
  generateRsaKeyPair,
  exportPubKey,
  rsaDecrypt,
  symDecrypt,
} from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;
  let lastCircuit: number[] | null = null;

  // Générer une paire de clés RSA pour ce nœud
  const keyPair = await generateRsaKeyPair();
  const publicKey = await exportPubKey(keyPair.publicKey);
  const privateKey = keyPair.privateKey;

  // Enregistrer le nœud auprès du registre
  try {
    await fetch(`http://localhost:8080/registerNode`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        nodeId,
        pubKey: publicKey,
      }),
    });
  } catch (error) {
    console.error(`Error registering node ${nodeId}:`, error);
  }

  // Route pour vérifier le statut du routeur
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // Route pour obtenir la clé privée du routeur
  onionRouter.get("/getPrivateKey", async (req, res) => {
    const exportedKey = await exportPrvKey(privateKey);
    res.json({ result: exportedKey });
  });

  // Route pour obtenir le dernier message chiffré reçu
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // Route pour obtenir le dernier message déchiffré reçu
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // Route pour obtenir la destination du dernier message
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Route pour obtenir le dernier circuit utilisé
  onionRouter.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // Route pour recevoir un message
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;
      lastReceivedEncryptedMessage = message;

      // Extraire la clé symétrique chiffrée et le contenu chiffré
      const keyBlockSize = 344;
      const encryptedSymKey = message.substring(0, keyBlockSize);
      const encryptedContent = message.substring(keyBlockSize);

      // Déchiffrer la clé symétrique avec la clé privée RSA
      const symKey = await rsaDecrypt(encryptedSymKey, privateKey);

      // Déchiffrer le contenu avec la clé symétrique
      const decryptedContent = await symDecrypt(symKey, encryptedContent);
      lastReceivedDecryptedMessage = decryptedContent;

      // Extraire le port de destination et le message restant
      const destinationStr = decryptedContent.substring(0, 10);
      const remainingMessage = decryptedContent.substring(10);

      const destinationPort = parseInt(destinationStr);
      lastMessageDestination = destinationPort;

      // Mettre à jour le circuit
      lastCircuit = [nodeId, destinationPort];

      // Transmettre le message au prochain nœud ou à l'utilisateur final
      await fetch(`http://localhost:${destinationPort}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: remainingMessage,
        }),
      });

      res.send("success");
    } catch (error) {
      console.error(`Error processing message at node ${nodeId}:`, error);
      res.status(500).send("error");
    }
  });

  // Démarrer le serveur
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}