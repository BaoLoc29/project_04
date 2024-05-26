import User from "../models/user.js"
import bcrypt from "bcryptjs"
import joi from "joi"
import jwt from "jsonwebtoken"

const tokenSecret = 'secret'
const formatCreatedAt = (date) => {
    return date.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

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
        const findUser = await User.findOne({ email }).lean()
        if (!findUser) {
            return res.status(401).json({
                error: "User not found"
            })
        }

        const checkPassword = compareSync(password, findUser.password)

        const accessToken = jwt.sign({
            id: findUser._id,
        }, process.env.SECRET_KEY, { expiresIn: '1d' })


        const {
            password: userPassword,
            ...returnUser
        } = findUser

        if (!checkPassword) {
            return res.status(401).json({
                error: "Incorrect password"
            })
        }
        if (findUser) {
            return res.status(200).json({
                message: "Login successful",
                user: returnUser,
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
export const createUser = async (req, res) => {
    const { hashSync, genSaltSync } = bcrypt;
    try {
        const { name, gender, phone, email, password, role } = req.body;

        const createSchema = joi.object({
            name: joi.string().required().messages({
                'string.empty': 'Name is required'
            }),
            gender: joi.boolean().required().messages({
                'boolean.empty': 'Gender is required'
            }),
            phone: joi.string().length(10).required().messages({
                "string.length": "Phone must have 10 digits",
                "any.required": "Please enter your Phone"
            }),
            email: joi.string().email().required().messages({
                'string.email': 'Invalid email',
                'string.empty': 'Email is required'
            }),
            password: joi.string().min(6).required().messages({
                'string.min': 'Password must be at least 6 characters',
                'string.empty': 'Password is required'
            }),
            role: joi.string().valid('manage', 'employee').required().messages({
                'string.empty': `Role is required`,
                'any.only': "Role must be either 'manage' or 'employee'"
            }),
        });

        const { error } = createSchema.validate({ name, gender, phone, email, password, role });
        if (error) {
            return res.status(400).json({
                error: error.details.map(e => e.message)
            });
        }

        const findUser = await User.findOne({ email });
        if (findUser) {
            return res.status(400).json({ message: "User email is already in use. Try using another email." });
        }

        // Xác định tiền tố cho e_code dựa trên vai trò
        let prefix;
        if (role === 'manage') {
            prefix = 'QL';
        } else if (role === 'employee') {
            prefix = 'NV';
        } else {
            return res.status(400).json({ message: "Invalid role. Role must be either 'manager' or 'employee'." });
        }

        // Tìm người dùng có e_code hiện có cao nhất dựa trên tiền tố
        const latestUser = await User.findOne({ e_code: new RegExp(`^${prefix}`) }).sort({ e_code: -1 }).exec();
        let newECode;
        if (latestUser && latestUser.e_code) {
            // Tách số ra khỏi chữ và tăng lên 1
            const latestECode = latestUser.e_code;
            const numericPart = parseInt(latestECode.slice(2)) + 1;
            newECode = `${prefix}${numericPart.toString().padStart(3, '0')}`;
        } else {
            newECode = `${prefix}001`;
        }

        const salt = genSaltSync();
        const hashedPassword = hashSync(password, salt);

        const result = await User.create({ e_code: newECode, name, gender, phone, email, password: hashedPassword, role });

        return res.status(200).json({
            message: "Account has been successfully created.",
            user: {
                ...result.toObject(),
                createdAt: formatCreatedAt(result.createdAt)
            }
        });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}
export const editUser = async (req, res) => {
    try {
        const { name, gender, phone, email, password, role } = req.body;
        const { id } = req.params;

        const editSchema = joi.object({
            name: joi.string().required().messages({
                'string.empty': 'Name is required'
            }),
            gender: joi.boolean().required().messages({
                'boolean.empty': 'Gender is required'
            }),
            phone: joi.string().length(10).required().messages({
                "string.length": "Phone must have 10 digits",
                "any.required": "Please enter your Phone"
            }),
            email: joi.string().email().required().messages({
                'string.email': 'Invalid email',
                'string.empty': 'Email is required'
            }),
            password: joi.string().min(6).required().messages({
                'string.min': 'Password must be at least 6 characters',
                'string.empty': 'Password is required'
            }),
            role: joi.string().valid('manage', 'employee').required().messages({
                'string.empty': `Role is required`,
                'any.only': "Role must be either 'manage' or 'employee'"
            }),
        })
        const { error } = editSchema.validate({ name, gender, phone, email, password, role });
        if (error) {
            return res.status(400).json({
                error: error.details.map(e => e.message)
            });
        }

        const findUserByEmail = await User.findOne({ email });
        if (findUserByEmail && findUserByEmail._id.toString() !== id) {
            return res.status(400).json({ message: "User email is already in use. Try using another email." });
        }

        const updateUser = await User.findByIdAndUpdate(id, {
            name, gender, email, phone, role
        }, { new: true }).select("-password")

        if (!updateUser) {
            return res.status(400).json({ message: "User is not found" })
        }

        let prefix;
        if (role === 'manage') {
            prefix = 'QL';
        } else if (role === 'employee') {
            prefix = 'NV';
        } else {
            return res.status(400).json({ message: "Invalid role. Role must be either 'manager' or 'employee'." });
        }

        if ((role === 'manage' && !updateUser.e_code.startsWith('QL')) ||
            (role === 'employee' && !updateUser.e_code.startsWith('NV'))) {
            // Tìm người dùng có mã nhân viên lớn nhất của vai trò mới
            const latestUser = await User.findOne({ e_code: new RegExp(`^${prefix}`) }).sort({ e_code: -1 }).exec();
            let newECode;
            if (latestUser && latestUser.e_code) {
                const latestECode = latestUser.e_code;
                const numericPart = parseInt(latestECode.slice(2)) + 1;
                newECode = `${prefix}${numericPart.toString().padStart(3, '0')}`;
            } else {
                newECode = `${prefix}001`;
            }

            // Cập nhật mã nhân viên mới cho người dùng
            updateUser.e_code = newECode;
            await updateUser.save();
        }

        return res.status(200).json({
            message: "Update successful",
            user: {
                ...updateUser.toObject(),
                createdAt: formatCreatedAt(updateUser.createdAt)
            }
        })
    } catch (error) {
        return res.status(500).json(
            { message: error.message }
        )
    }
}
export const deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findByIdAndDelete(id);
        if (!user) {
            return res.status(400).json({ message: "User is not found" })
        }
        return res.status(200).json({ message: "Delete successful" })
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}
export const getPagingUser = async (req, res) => {
    try {
        const query = req.query
        const users = await User.find({ role: "employee" })
            .skip(query.pageSize * query.pageIndex - query.pageSize)
            .limit(query.pageSize).sort({ createdAt: "desc" })

        const countusers = await User.countDocuments({ role: "employee" })
        const totalPage = Math.ceil(countusers / query.pageSize)

        // Format createdAt for each user
        const formattedUsers = users.map(user => ({
            ...user.toObject(),
            createdAt: formatCreatedAt(user.createdAt)
        }));

        return res.status(200).json({ users: formattedUsers, totalPage, count: countusers })
    } catch (error) {
        return res.status(500).json(error)
    }
}
export const searchUser = async (req, res) => {
    try {
        const { keyword, option } = req.body;

        if (!keyword || !option) {
            const noKeyword = await User.find()
            return res.status(200).json({ noKeyword });
        }

        let searchField = {};
        if (option === "name") {
            searchField = { name: { $regex: keyword, $options: 'i' } };
        } else if (option === "email") {
            searchField = { email: { $regex: keyword, $options: 'i' } };
        } else if (option === "e_code"){
            searchField = { e_code: { $regex: keyword, $options: 'i' } };
        }

        const users = await User.find({ ...searchField, role: 'employee' });

        if (!users || users.length === 0) {
            return res.status(404).json({ message: "User is not found" });
        }

        const formattedUsers = users.map(user => ({
            ...user.toObject(),
            createdAt: formatCreatedAt(user.createdAt)
        }));

        return res.status(200).json({ users: formattedUsers });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
};
export const getUserById = async (req, res) => {
    try {
        const userId = req.params.id
        const user = await User.findById(userId)

        if (!user) {
            return res.status(404).json({ message: "User is not found" });
        }

        return res.status(200).json({ user })

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
        const user = await User.findById(id)
        if (!user) {
            return res.status(404).json({ message: "User is not found" });
        }

        const checkPassword = compareSync(oldPassword, user.password)
        if (!checkPassword) {
            return res.status(400).json({ message: "Old password is incorrect" })
        }

        const salt = genSaltSync()
        const hashPassword = hashSync(newPassword, salt)

        const updatePassword = await User.findByIdAndUpdate(id, {
            password: hashPassword
        }).select("-password")

        return res.status(200).json({
            message: "Update password successfull",
            user: updatePassword
        })
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}