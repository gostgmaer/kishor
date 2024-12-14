const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
    {
        // Basic User Details
        firstName: {
            type: String,
            required: true,
            trim: true,
        },
        lastName: {
            type: String,
            required: true,
            trim: true,
        },
        username: {
            type: String,
            unique: true,
            sparse: true,
            trim: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
        },
        password: {
            type: String,
            required: true,
        },

        // Authentication & Security
        role: {
            type: String,
            enum: ['user', 'moderator', 'admin', 'superadmin'],
            default: 'user',
        },
        isActive: {
            type: Boolean,
            default: true,
        },
        isVerified: {
            type: Boolean,
            default: false,
        },
        emailVerificationToken: {
            type: String, // Token for email verification
        },
        emailVerificationExpires: {
            type: Date,
        },
        resetPasswordToken: {
            type: String,
        },
        resetPasswordExpires: {
            type: Date,
        },

        // Two-Factor Authentication
        twoFactorEnabled: {
            type: Boolean,
            default: false,
        },
        twoFactorCode: {
            type: String,
        },
        twoFactorExpires: {
            type: Date,
        },

        // User Profile
        profilePicture: {
            type: String,
        },
        coverPhoto: {
            type: String, // Cover photo for user profile
        },
        bio: {
            type: String, // Short biography or description
        },
        phone: {
            type: String,
            unique: true,
            sparse: true,
        },
        address: {
            street: { type: String },
            city: { type: String },
            state: { type: String },
            country: { type: String },
            zipCode: { type: String },
        },
        dateOfBirth: {
            type: Date,
        },
        gender: {
            type: String,
            enum: ['male', 'female', 'non-binary', 'prefer not to say'],
        },

        // Social & Interaction
        friends: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
            },
        ],
        followers: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
            },
        ],
        following: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
            },
        ],

        // Account Metadata
        lastLogin: {
            type: Date,
        },
        loginAttempts: {
            type: Number,
            default: 0,
        },
        lockUntil: {
            type: Date,
        },
        accountCreatedIp: {
            type: String, // IP address when the account was created
        },
        lastLoginIp: {
            type: String, // IP address of the last login
        },

        // Notifications & Preferences
        preferences: {
            notifications: {
                email: { type: Boolean, default: true },
                sms: { type: Boolean, default: false },
                push: { type: Boolean, default: true },
            },
            theme: {
                type: String,
                enum: ['light', 'dark', 'system'],
                default: 'system',
            },
            language: {
                type: String,
                default: 'en',
            },
        },

        // Social Authentication
        googleId: { type: String },
        facebookId: { type: String },
        twitterId: { type: String },
        linkedinId: { type: String },
        githubId: { type: String },
        appleId: { type: String },

        // Subscription & Billing
        subscription: {
            plan: {
                type: String,
                enum: ['free', 'basic', 'premium', 'enterprise'],
                default: 'free',
            },
            paymentMethod: {
                type: String,
                enum: ['credit_card', 'paypal', 'bank_transfer'],
            },
            startedAt: {
                type: Date,
            },
            expiresAt: {
                type: Date,
            },
            isTrial: {
                type: Boolean,
                default: false,
            },
        },
        billingAddress: {
            street: { type: String },
            city: { type: String },
            state: { type: String },
            country: { type: String },
            zipCode: { type: String },
        },

        // Analytics
        deviceInfo: {
            os: { type: String }, // Operating system of the user's device
            browser: { type: String }, // Browser name
            deviceType: { type: String }, // Mobile, desktop, tablet, etc.
        },
        usageStats: {
            totalLogins: { type: Number, default: 0 },
            totalTimeSpent: { type: Number, default: 0 }, // In minutes
        },

        // E-Commerce Related Fields
        wishlist: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'Product',
            },
        ],
        cart: [
            {
                product: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'Product',
                },
                quantity: {
                    type: Number,
                    default: 1,
                },
            },
        ],
        orders: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'Order',
            },
        ],
        reviews: [
            {
                product: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'Product',
                },
                review: { type: String },
                rating: { type: Number },
            },
        ],

        // Timestamps

    },
    {
        timestamps: true,

    }
);

// Virtual field for fullName
userSchema.virtual('fullName').get(function () {
    return `${this.firstName} ${this.lastName}`.trim();
});

// Pre-save hook for password hashing
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Password comparison method
userSchema.methods.comparePassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);
