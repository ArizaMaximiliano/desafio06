import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GithubStrategy } from 'passport-github2';

import { createHash, isValidPassword } from '../utils.js';
import UserModel from '../models/userModel.js';

const opts = {
    usernameField: 'email',
    passReqToCallback: true,
};

const githubOpts = {
    clientID: 'Iv1.a14400d009b934f4', // Este dato debe ser pasado por parametro
    clientSecret: 'fa0c70bb242d6fd814b17df0785416e4b87c2a0a', // Este dato debe ser pasado por parametro
    callbackURL: "http://localhost:8080/api/sessions/githubcallback", // Este dato debe ser pasado por parametro
};


export const initializePassport = () => {

    passport.use('register', new LocalStrategy(opts, async (req, email, password, done) => {
        try {
            const user = await UserModel.findOne({ email });
            if (user) {
                return done(new Error('Usuario ya registrado'));
            }
            const newUser = await UserModel.create({
                ...req.body,
                password: createHash(password),
            });
            done(null, newUser);
        } catch (error) {
            done(new Error(`Ocurrio un error en la autenticacion ${error.message}`));
        }
    }));

    passport.use('login', new LocalStrategy(opts, async (req, email, password, done) => {
        try {
            const user = await UserModel.findOne({ email });

            // Verificación hardcoded para el rol de administrador
            if (email === 'adminCoder@coder.com' && password === 'adminCod3r123') {
                req.session.user = { email, role: 'admin' };
                return done(null, { email, role: 'admin' });
            }

            if (!user) {
                return done(new Error('Correo o contraseña invalidos 😨'));
            }

            const isPassValid = isValidPassword(password, user);
            if (!isPassValid) {
                return done(new Error('Correo o contraseña invalidos 😨'));
            }

            req.session.user = { email, role: 'usuario' };
            done(null, user); // Se autentica al usuario normal

        } catch (error) {
            done(new Error(`Ocurrio un error durante la autenticacion ${error.message} 😨.`));
        }
    }));

    passport.use('github', new GithubStrategy(githubOpts, async (accessToken, refreshToken, profile, done) => {
        console.log('profile', profile);
        let email = profile._json.email;
        let user = await UserModel.findOne({ email });

        if (!user) {
            user = {
                firstName: profile._json.name,
                lastName: '',
                age: 22,
                email: email,
                password: '',
                provider: 'Github',
            };

            const newUser = await UserModel.create(user);
            done(null, newUser);
        } else {
            return done(null, user);
        }

    }));


    passport.serializeUser((user, done) => {
        if (user.role === 'admin') {
            const adminId = 'adminUniqueId'; // Identificador único para el usuario admin
            done(null, adminId);
        } else {
            done(null, user.id); // Usar el ID del usuario normal
        }
    });

    passport.deserializeUser(async (id, done) => {
        if (id === 'adminUniqueId') {
            const admin = { email: 'adminCoder@coder.com', role: 'admin' }; // Datos del usuario admin
            done(null, admin);
        } else {
            try {
                const user = await UserModel.findById(id);
                done(null, user);
            } catch (error) {
                done(error, null);
            }
        }
    });



}

