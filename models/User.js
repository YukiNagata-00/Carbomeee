const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        min:1,
        max:25,
    },
    email: {
        type: String,
        required: true,
        max: 50,
        unique: true,
    },
    email2: {
        type: String,
        max: 50,
        index: true,
        sparse: true,
        default: ''
    },
    password: {
        type: String,
        required: true,
        min:5,
        max:20,
    },
    favorites:{
        type: Array,
        default: [],
    },
    addcards:{
        type: Array,
        default: [],
    },
    lastLogin: {
        type: Date,
        default: Date
    },
    loginCount: {
        type: Number,
        default: 0
    },
    learningCount: {
        type: Number,
        default: 0
    },
    passwordResetToken: { 
        type: String 
    },
    passwordResetExpires: { 
        type: Date 
    },
},
    {timestamps: true}
);
UserSchema.index({ email2: 1 }, { unique: false });
module.exports = mongoose.model("User", UserSchema);