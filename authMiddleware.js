const jwt = require("jsonwebtoken");

const verifierToken = (req, res, next) => {
  // Récupérer l'en-tête Authorization
  const authHeader = req.headers["authorization"];

  // Le format attendu est "Bearer <token>"
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ erreur: "Accès refusé. Jeton d'authentification manquant." });
  }

  try {
    // Vérifier et décoder le token avec le secret
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Stocker les infos de l'utilisateur dans l'objet de la requête pour les utiliser plus tard
    req.user = decoded;

    next(); // Passer à la suite (la route proprement dite)
  } catch (err) {
    return res.status(403).json({ erreur: "Jeton invalide ou expiré." });
  }
};

module.exports = verifierToken;
