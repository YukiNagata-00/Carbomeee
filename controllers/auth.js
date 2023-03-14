const User = require("../models/User");
const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const validation = require('../handlers/validatioin');
const tokenHandler = require('../handlers/tokenHandler');
const  fetchInstance  = require('./fetchInstance.js');
const nodemailer = require('nodemailer');
//const sendmail = require('sendmail')();
// const sendmail = require('sendmail')({
//     smtpPort: 25,
//     smtpHost: 'ALT1.ASPMX.L.GOOGLE.COM',
//     smtpTimeout: 10000, // Increase the timeout value to 10 seconds
// });
require('../app');
var path = require('path');

//ユーザー登録API
const userRegister =  [
    //バリデーション
    body('username').isLength({min: 1, max: 25 }).withMessage('ユーザー名は１~25文字にしてください'),
    body('email').isEmail().withMessage('正しいメールアドレスを入力してください'),
    body('password').isLength({min: 5, max: 20 }).withMessage('パスワードは5~20文字にしてください'),
    body('passwordConfirmation').isLength({min: 5, max: 20 }).withMessage('確認用パスワードは5~20文字にしてください'),
    body('passwordConfirmation').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Password confirmation does not match password');
        }else{
            return true;
        }
    }),
    body('email').custom((value, { req }) => {
        return new Promise((resolve, reject) => {
            User.findOne({ email: req.body.email }, function(err, user) {
                if (err) {
                    reject(new Error("Server Error"));
                }
                if (Boolean(user)) {
                    reject(new Error("E-mail already in use"));
                }
                resolve(true);
            });
        });
    }),
    validation.validate,
    async(req, res) =>{
    const password = req.body.password;
    try{

        //パスワード暗号化
        req.body.password = CryptoJS.AES.encrypt(password, process.env.PASSWORD_KEY);
        //ユーザーの新規作成
        const user = await User.create(req.body);
        //jwt
        const token = jwt.sign({ id: user._id }, process.env.TOKEN_SECRET_KEY,  { expiresIn: '24h' });

        return res.status(200).json({user, token});
    }catch(err){
        return res.status(500).json(err);
    }

},]

//ログインAPI
const userLogin = [
    body('email').isEmail().withMessage('正しいメールアドレスを入力してね'),
    body('password').isLength({min: 5, max: 20 }).withMessage('正しいパスワードを入力してね'),
    validation.validate,

    async(req, res)=>{
        const {email, password} = req.body;
        try{
            //DBからemailが一致するものを探す
            const user = await User.findOne({email: email});
            if(!user){
                return res.status(401).json({
                    errors:{
                        param: 'email',
                        message: 'emailが違うよ'
                    }
                })
            }
            //パスワード認証
            const decryptedPassword = CryptoJS.AES.decrypt(user.password, process.env.PASSWORD_KEY).toString(CryptoJS.enc.Utf8);
            if(password !== decryptedPassword){
                return res.status(401).json({
                    errors:{
                        param: 'password',
                        message: 'パスワードが違うよ'
                    }
                })
            }
            //jwtの発行
            const token = jwt.sign({ id: user._id }, process.env.TOKEN_SECRET_KEY,  { expiresIn: '24h' });
            console.log('login success');
            return res.status(201).json({user, token});
        
        }catch(err){
            return res.status(500).json({
                errors:{
                    param: 'database',
                    message: 'データベースエラーが発生しました'
                }
            });
        }
    }
]

//JWT認証API
const verifyToken =[tokenHandler.verifyToken, (req, res)=>{
    return res.status(201).json({user: req.user});
}]
//add 1 loginCount
const updateLoginCount = async (req, res) =>{
    try{
        const userId = req.body.userId;
        const user = await User.findById(userId);
        console.log(user);
        user.loginCount +=1;
        await user.save();
        res.status(200);

    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
//DBの「learningCount」に+10
const updateLearningCount = async (req, res) =>{
    try{
        const userId = req.body.userId;
        const user = await User.findById(userId);
        console.log(user);
        user.learningCount += 10;
        await user.save();
        res.status(200);

    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
}

//ユーザー情報編集
const updateUserInfo = [
    //バリデーション
    body('username').isLength({min: 1, max: 25 }).withMessage('ユーザー名は１~25文字にしてください'),
    body('email').isEmail().withMessage('正しいメールアドレスを入力してください'),
    body('email2')
    .optional()
    .custom((value, { req }) => {
        if (value && !validator.isEmail(value)) {
        throw new Error('正しいメールアドレスを入力してください');
        }
        return true;
    }).withMessage('正しいメールアドレスを入力してください'),
    (req, res, next) => {
        if (req.body.newPassword) {
            body('newPassword').isLength({min: 5, max: 20 }).withMessage('パスワードは5~20文字にしてください')(req, res, next);
        } else {
            next();
        }
    },
    body('email').custom(async (value, { req }) => {
        try {
            const user = await User.findById(req.body.userId);
            if (user.email === value) {
                return true;
            }
            const userWithEmail = await User.findOne({ email: value });
            if (userWithEmail && userWithEmail._id.toString() !== req.body.userId) {
                throw new Error('このメールアドレスはすでに使われています');
            }
            return true;
        } catch (err) {
            console.log(err)
            throw new Error('Server Errore', err);
        }
    }).withMessage('このメールアドレスはすでに使われています'),
    validation.validate,
    async (req, res) => {
        let currentPassword = req.body.currentPassword;
        const newPassword = req.body.newPassword;
        let  encryptedPassword;

        if (currentPassword && !newPassword) {
            return res.status(400).json({ message: '新しいパスワードを入力してください' });
        } else if (!currentPassword && newPassword) {
            return res.status(400).json({ message: '現在のパスワードを入力してください' });
        }else{
            try {
                if(currentPassword && newPassword){
                        //現在のパスワードがあっているかチェック
                        const user = await User.findById(req.body.userId);
                        
                        if (user) {
                            //パスワード認証
                            const decryptedPassword = CryptoJS.AES.decrypt(user.password, process.env.PASSWORD_KEY).toString(CryptoJS.enc.Utf8);
                            if(currentPassword !== decryptedPassword){
                                return res.status(401).json({
                                    errors:{
                                        param: 'password',
                                        message: '現在のパスワードが違います'
                                    }
                                })
                            }
                        }else{
                            return res.status(401).json({
                                errors:{
                                    param: 'password',
                                    message: '現在のパスワードが違います'
                                }
                            })
                        }
                    // 新しいパスワードをハッシュ化
                    encryptedPassword = CryptoJS.AES.encrypt(newPassword, process.env.PASSWORD_KEY).toString();
                }
                const updatedUser = await User.findByIdAndUpdate(req.body.userId, {
                    $set: {
                        username: req.body.username,
                        email: req.body.email, 
                        email2: req.body.email2,
                        password: encryptedPassword,
                    },
                });
                // JWT token
                const token = jwt.sign({ id: updatedUser._id }, process.env.TOKEN_SECRET_KEY, { expiresIn: '24h' });
                return res.status(200).json({ user: updatedUser, token });
            } catch (err) {
                console.log(err)
                return res.status(500).json({ err: 'Internal server error' });
            }
        }

    },
];

//パスワード再設定メール送信API
const sendPasswordEmail = [
    //バリデーション
    body('email').isEmail().withMessage('正しいメールアドレスを入力してください'),
    body('email').custom(async (value, { req }) => {
        try {

            const user = await User.findOne({ email: value });
            if (!user) {
                throw new Error('ユーザーが見当たりません');
            }
            return true;
        } catch (err) {
            console.log(err)
            throw new Error('Server Errore', err);
        }
    }).withMessage('ユーザーが見当たりません'),
    validation.validate,
    async (req, res) => {
        try {
            const user = await User.findOne({email: req.body.email});
            const token = CryptoJS.HmacSHA256('sha256', process.env.PASSWORD_KEY);
            user.passwordResetToken = token;
            user.passwordResetExpires = Date.now() + 3600000; //1h
            await user.save();

            const passwordResetUrl =  process.env.APP_URL+'auth/show-reset-password/'+ token +'?email='+ encodeURIComponent(req.body.email);
            console.log(passwordResetUrl)
            
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: req.body.email,
                    pass: process.env.MAIL_APP_PASS,
                },
            });

            try {
                // メール送信
                // sendmail({
                //     from: 'from@example.com',
                //     to: req.body.email,
                //     subject: 'メールのタイトルです',
                //     text: 'メールの本文です。この例はテキストです。html形式でもOK。',
                //     timeout: 10000
                // }, function(err, reply) {
                //     console.log(err && err.stack);
                //     console.dir(reply);
                //     console.log('send!')
                // });
                transporter.sendMail({
                    from: 'from@example.com',
                    to: req.body.email,
                    text: "以下のURLをクリックしてパスワードを再発行してください。\n\n"+ passwordResetUrl,
                    subject: 'パスワード再発行メール',
                });
                //res.json({ result: true });
            } catch (error) {
                console.log(error)
                return res.status(500).json({ error: 'Failed to send email' });
            }
            
        } catch (error) {
            console.log(error)
            return res.status(500).json({ error: 'Internal server error' });
        }
        
    
        return res.status(200).json({msg: "success!!"});
    },
];

const showResetPasswordPage = async(req, res) =>{
    const { token } = req.params;
    try {
        const user = await User.findOne({ passwordResetToken: token, passwordResetExpires: { $gt: Date.now() } });
        console.log(user)
        if (!user) {
            return res.status(404).send('Invalid token or token expired');
        }
        res.sendFile(path.join(__dirname, '../public', 'auth/resetPassword.html'));
    } catch (error) {
        console.log(error)
        return res.status(500).json({ error: 'Internal server error' });
    }
}


const resetPassword =  [
    body('password').isLength({min: 5, max: 20 }).withMessage('パスワードは5~20文字にしてください'),
    body('passwordConfirmation').isLength({min: 5, max: 20 }).withMessage('確認用パスワードは5~20文字にしてください'),
    body('passwordConfirmation').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Password confirmation does not match password');
        }else{
            return true;
        }
    }),
    validation.validate,
    async (req, res) => {
        let currentPassword = req.body.currentPassword;
        const newPassword = req.body.newPassword;
        let  encryptedPassword;

        if (currentPassword && !newPassword) {
            return res.status(400).json({ message: '新しいパスワードを入力してください' });
        } else if (!currentPassword && newPassword) {
            return res.status(400).json({ message: '現在のパスワードを入力してください' });
        }else{
            try {
                
                    // 新しいパスワードをハッシュ化
                    encryptedPassword = CryptoJS.AES.encrypt(newPassword, process.env.PASSWORD_KEY).toString();
                    const updatedUser = await User.findByIdAndUpdate(req.body.userId, {
                    $set: {
                        password: encryptedPassword,
                        passwordResetToken: undefined,
                        passwordResetExpires: undefined
                    },
                });
                return res.status(200).json({ user: updatedUser, msg: "Password reset"});
            } catch (err) {
                console.log(err)
                return res.status(500).json({ err: 'Internal server error' });
            }
        }

    },
];

module.exports = {userRegister,
    userLogin, 
    verifyToken,
    updateLoginCount,
    updateLearningCount,
    updateUserInfo,
    sendPasswordEmail,
    showResetPasswordPage,
    resetPassword
};