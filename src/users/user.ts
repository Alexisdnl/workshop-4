import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT } from "../config";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  // Route pour vérifier le statut de l'utilisateur
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route pour obtenir le dernier message reçu
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route pour obtenir le dernier message envoyé
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Route pour obtenir le dernier circuit utilisé
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // Route pour recevoir un message
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  // Route pour envoyer un message
  _user.post("/sendMessage", (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;
    lastSentMessage = message;
    lastCircuit = [userId, destinationUserId]; // Simuler un circuit simple
    res.send("success");
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}