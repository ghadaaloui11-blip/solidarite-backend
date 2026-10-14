const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
require("dotenv").config();

const verifierToken = require("./authMiddleware");

const app = express();
app.use(express.json());
app.use(cors());

// Configuration de la connexion PostgreSQL
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "solidarite_db",
  password: "postgrespw",
  port: 5432,
});

// Test de la connexion à la base de données
pool
  .connect()
  .then(() =>
    console.log("Connecté à la base de données PostgreSQL (solidarite_db)")
  )
  .catch((err) =>
    console.error("Erreur de connexion à la base de données", err)
  );

// Configuration de Multer pour l'upload d'images
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Les images seront stockées dans le dossier /uploads
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Nom unique
  },
});
const upload = multer({ storage: storage });

// US01 : Inscription d'un utilisateur
app.post("/api/auth/inscription", async (req, res) => {
  try {
    const {
      nom,
      email,
      telephone,
      motDePasse,
      role,
      nomAssociation,
      adresse,
      matriculeFiscal,
      prenom,
    } = req.body || {};

    if (!email || !motDePasse || !role) {
      return res.status(400).json({
        erreur:
          "Veuillez remplir tous les champs obligatoires (email, motDePasse, role).",
      });
    }

    const userCheck = await pool.query(
      "SELECT * FROM utilisateur WHERE email = $1",
      [email]
    );
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ erreur: "Cet email est déjà utilisé." });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(motDePasse, saltRounds);

    const newUserQuery = `
        INSERT INTO utilisateur (nom, email, telephone, mot_de_passe_hache, role) 
        VALUES ($1, $2, $3, $4, $5) RETURNING id, nom, email, role;
    `;
    const newUser = await pool.query(newUserQuery, [
      nom,
      email,
      telephone,
      hashedPassword,
      role,
    ]);
    const userId = newUser.rows[0].id;

    if (role === "association") {
      await pool.query(
        "INSERT INTO association (id, nom_association, adresse, matricule_fiscal) VALUES ($1, $2, $3, $4)",
        [userId, nomAssociation, adresse, matriculeFiscal]
      );
    } else if (role === "citoyen") {
      await pool.query("INSERT INTO citoyen (id, prenom) VALUES ($1, $2)", [
        userId,
        prenom,
      ]);
    }

    res.status(201).json({
      message: "Inscription réussie avec succès !",
      utilisateur: newUser.rows[0],
    });
  } catch (err) {
    console.error("ERREUR EXACTE :", err);
    res
      .status(500)
      .json({ erreur: "Erreur lors de l'inscription.", details: err.message });
  }
});

// US29 : Connexion sécurisée
app.post("/api/auth/connexion", async (req, res) => {
  try {
    const { email, motDePasse } = req.body;

    const userQuery = await pool.query(
      "SELECT * FROM utilisateur WHERE email = $1",
      [email]
    );
    if (userQuery.rows.length === 0) {
      return res
        .status(400)
        .json({ erreur: "Email ou mot de passe incorrect." });
    }

    const utilisateur = userQuery.rows[0];

    const isValidPassword = await bcrypt.compare(
      motDePasse,
      utilisateur.mot_de_passe_hache
    );
    if (!isValidPassword) {
      return res
        .status(400)
        .json({ erreur: "Email ou mot de passe incorrect." });
    }

    const token = jwt.sign(
      { id: utilisateur.id, role: utilisateur.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Connexion réussie",
      token,
      utilisateur: {
        id: utilisateur.id,
        nom: utilisateur.nom,
        email: utilisateur.email,
        role: utilisateur.role,
      },
    });
  } catch (err) {
    console.error("ERREUR EXACTE :", err);
    res
      .status(500)
      .json({ erreur: "Erreur lors de la connexion.", details: err.message });
  }
});

// Route test protégée par le middleware JWT
app.get("/api/auth/profil-protege", verifierToken, (req, res) => {
  res.json({
    message: "Accès autorisé !",
    utilisateurConnecte: req.user,
  });
});

// US05 : Création d'un signalement par le citoyen (Protégé par token + Multer pour la photo)
app.post(
  "/api/signalements",
  verifierToken,
  upload.single("photo"),
  async (req, res) => {
    try {
      const { description, latitude, longitude, est_anonyme } = req.body;

      // Récupérer le chemin du fichier image s'il existe
      const photoPath = req.file ? req.file.path : null;

      // Récupérer l'ID du citoyen connecté via le token JWT
      const citoyenId = req.user.id;

      // Gérer l'anonymat (convertir en booléen)
      const estAnonymeBool = est_anonyme === "true" || est_anonyme === true;
      const finalCitoyenId = estAnonymeBool ? null : citoyenId;

      if (!description) {
        return res
          .status(400)
          .json({ erreur: "La description est obligatoire." });
      }

      // Conversion sécurisée des coordonnées GPS en nombres décimaux
      const latValue = latitude ? parseFloat(latitude) : null;
      const lonValue = longitude ? parseFloat(longitude) : null;

      const query = `
      INSERT INTO signalement (description, photo, latitude, longitude, est_anonyme, citoyen_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `;

      const values = [
        description,
        photoPath,
        latValue,
        lonValue,
        estAnonymeBool,
        finalCitoyenId,
      ];

      const newSignalement = await pool.query(query, values);

      res.status(201).json({
        message: "Signalement créé avec succès !",
        signalement: newSignalement.rows[0],
      });
    } catch (err) {
      console.error("ERREUR EXACTE :", err);
      res
        .status(500)
        .json({
          erreur: "Erreur lors de la création du signalement.",
          details: err.message,
        });
    }
  }
);

// Lancement du serveur à la fin
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});
