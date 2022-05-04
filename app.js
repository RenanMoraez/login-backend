/**
 *
 * imports
 *
 */

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

/**
 * Configurar JSON response
 */
app.use(express.json());

/**
 * Models
 */
const User = require("./models/User");

/**
 * Open Route - Public Route
 */
app.get("/", (req, res) => {
  res.status(200).json({ msg: "bem vindo a nossa API" });
});


/**
 * Private Route
 */
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id

    //check if user exists
    const user = await User.findById(id, '-password');

    if(!user){
        return res.status(404).json({msg:'Usuario não encontrado'})
    }

    res.status(200).json({user})

})


/**
 * função para verificar um token
 */

function checkToken(req, res, next){

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({ msg:'acesso negado'})
    }


    try {

        const secret = process.env.SECRET;

        jwt.verify(token, secret);

        next();        
    } catch (error) {
        res.status(400).json({msg: "token invalido"})
    }
}



/**
 * Registrando um usuario
 */
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  /**
   * validação
   */
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório" });
  }
  if (!email) {
    return res.status(422).json({ msg: "O E-mail é obrigatório" });
  }
  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatório" });
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "As senhas não conferem" });
  }

  //check if user exists
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: "Por favor, ultilize outro e-mail" });
  }

  /**
   * criando a senha
   */

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  /**
   * Criando o usuario
   */

  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: "O usuario criado com sucesso" });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({
        msg: "Aconteceu um erro no servidor tente novamento mais tarde",
      });
  }
});

/**
 * Login de usuario
 */
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  /**
   * Validação
   */
  if (!email) {
    return res.status(422).json({ msg: "O E-mail é obrigatório" });
  }
  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatório" });
  }


    //check if user exists
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.status(404).json({ msg: "Usuario não encontrado" });
    }

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
      return res.status(422).json({ msg: "senha inválida" });

    }

    try {
        
        const secret = process.env.SECRET;
        const token = jwt.sign({
            id: user._id,
        }, secret)

        res.status(200).json({ msg: "Autenticação realizada com sucesso", token})

    } catch (error) {
        console.log(error);
        res
          .status(500)
          .json({
            msg: "Aconteceu um erro no servidor tente novamento mais tarde",
          });
    }
});
 

/**
 * credenciais
 */
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

/**
 * Conectando com o banco de dados
 */
mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.uwncb.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("conectou com o banco");
  })
  .catch((err) => console.log(err));
