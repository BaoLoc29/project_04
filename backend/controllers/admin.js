import Admin from "../models/admin.js"
import bcrypt from "bcryptjs"
import joi from "joi"
import jwt from "jsonwebtoken"

const tokenSecret = 'secret'
export const login = async (req, res) => {
    const { compareSync } = bcrypt
    try {
        const email = req.body.email
        const password = req.body.password

        const loginSchema = joi.object({
            email: joi.string().email().min(3).max(32).required().messages({
                "string.email": "Invalid email format",
                "string.min": "Email must be at least 3 characters",
                "string.max": "Email must not exceed 32 characters"
            }),
            password: joi.string().min(6).max(32).required().messages({
                "string.password": "Invalid password format",
                "string.min": "Password must be at least 6 characters",
                "string.max": "Password must not exceed 32 characters"
            }),
        })

        const validate = loginSchema.validate({ email, password })

        if (validate.error) {
            return res.status(400).json({
                error: validate.error.details[0].message
            })
        }
        const findAmin = await Admin.findOne({ email }).lean()
        if (!findAmin) {
            return res.status(401).json({
                error: "Admin not found"
            })
        }

        const checkPassword = compareSync(password, findAmin.password)

        const accessToken = jwt.sign({
            id: findAmin._id,
        }, process.env.SECRET_KEY, { expiresIn: '1d' })


        const {
            password: adminPassword,
            ...returnAdmin
        } = findAmin

        if (!checkPassword) {
            return res.status(401).json({
                error: "Incorrect password"
            })
        }
        if (findAmin) {
            return res.status(200).json({
                message: "Login successful",
                admin: returnAdmin,
                accessToken
            })
        }
    } catch (error) {
        console.error(error);
        if (error.details) {
            // Nếu có lỗi từ Joi, trả về thông báo lỗi từ Joi
            const errorMessage = error.details.map((detail) => detail.message).join(', ');
            return res.status(400).json({ message: errorMessage });
        } else {
            // Nếu có lỗi khác, trả về thông báo lỗi mặc định
            return res.status(500).json({ message: "Failed to Sign In" });
        }
    }
}
export const createAdmin = async (req, res) => {
    const { hashSync, genSaltSync } = bcrypt;
    try {
        const { name, phone, email, password } = req.body;

        const createSchema = joi.object({
            email: joi.string().email().required().messages({
                'string.email': 'Invalid email',
                'string.empty': 'Email is required'
            }),
            password: joi.string().min(6).required().messages({
                'string.min': 'Password must be at least 6 characters',
                'string.empty': 'Password is required'
            }),
            name: joi.string().required().messages({
                'string.empty': 'Name is required'
            }),
            phone: joi.string().min(10).max(10).required().messages({
                "string.min": "Phone must have a minimum of 10 digits",
                "string.max": "Phone must have a maximum of 10 digits",
                "any.required": "Please enter your Phone"
            }),
        });

        const { error } = createSchema.validate({ name, phone, email, password });
        if (error) {
            return res.status(400).json({
                error: error.details.map(e => e.message)
            });
        }

        const findAdmin = await Admin.findOne({ email });
        if (findAdmin) {
            return res.status(400).json({ message: "Admin email is already in use. Try using another email." });
        }

        const salt = genSaltSync();
        const hashedPassword = hashSync(password, salt);

        const result = await Admin.create({ name, phone, email, password: hashedPassword });

        return res.status(200).json({
            message: "Account has been successfully created.",
            ...result.toObject(),
        });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}
export const editAdmin = async (req, res) => {
    try {
        const { name, phone, email, password } = req.body;
        const { id } = req.params;

        const editSchema = joi.object({
            email: joi.string().email().required().messages({
                'string.email': 'Invalid email',
                'string.empty': 'Email is required'
            }),
            password: joi.string().min(6).required().messages({
                'string.min': 'Password must be at least 6 characters',
                'string.empty': 'Password is required'
            }),
            name: joi.string().required().messages({
                'string.empty': 'Name is required'
            }),
            phone: joi.string().min(10).max(10).required().messages({
                "string.min": "Phone must have a minimum of 10 digits",
                "string.max": "Phone must have a maximum of 10 digits",
                "any.required": "Please enter your Phone"
            }),
        })
        const { error } = editSchema.validate({ name, phone, email, password });
        if (error) {
            return res.status(400).json({
                error: error.details.map(e => e.message)
            });
        }

        const findAdmin = await Admin.findOne({ email });
        if (findAdmin) {
            return res.status(400).json({ message: "Admin email is already in use. Try using another email." });
        }

        const updateAdmin = await Admin.findByIdAndUpdate(id, {
            name, email, phone
        }, { new: true }).select("-password")

        if (!updateAdmin) {
            return res.status(400).json({ message: "Admin is not found" })
        }

        return res.status(200).json({
            message: "Update successful",
            admin: {
                ...updateAdmin.toObject()
            }
        })
    } catch (error) {
        return res.status(500).json(
            { message: error.message }
        )
    }
}
export const getAdminById = async (req, res) => {
    try {
        const adminId = req.params.id
        const admin = await Admin.findById(adminId)

        if (!admin) {
            return res.status(404).json({ message: "Admin is not found" });
        }

        return res.status(200).json({ admin })

    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}
export const changePassword = async (req, res) => {
    const { compareSync, genSaltSync, hashSync } = bcrypt
    try {
        const id = req.params.id
        const oldPassword = req.body.oldPassword
        const newPassword = req.body.newPassword

        const changePasswordSchema = joi.object({
            oldPassword: joi.string().min(6).max(32).required().messages({
                'string.empty': `oldPassword is required`,
                'string.min': `oldPassword must be at least 6 characters`,
                'string.max': `oldPassword must be at most 32 characters`,
                'any.required': `oldPassword is required`
            }),
            newPassword: joi.string().min(6).max(32).required().messages({
                'string.empty': `newPassword is required`,
                'string.min': `newPassword must be at least 6 characters`,
                'string.max': `newPassword must be at most 32 characters`,
                'any.required': `newPassword is required`
            })
        })
        const { error } = changePasswordSchema.validate({ oldPassword, newPassword })
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }
        const admin = await Admin.findById(id)
        if (!admin) {
            return res.status(404).json({ message: "Admin is not found" });
        }

        const checkPassword = compareSync(oldPassword, admin.password)
        if (!checkPassword) {
            return res.status(400).json({ message: "Old password is incorrect" })
        }

        const salt = genSaltSync()
        const hashPassword = hashSync(newPassword, salt)

        const updatePassword = await Admin.findByIdAndUpdate(id, {
            password: hashPassword
        }).select("-password")

        return res.status(200).json({
            message: "Update password successfull",
            admin: updatePassword
        })
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}