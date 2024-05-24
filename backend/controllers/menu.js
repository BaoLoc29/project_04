import Menu from "../models/menu.js";
import joi from "joi"

const formatCreatedAt = (date) => {
    return date.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

export const createMenu = async (req, res) => {
    try {
        const { code, name, classify, description, unit, price, discount } = req.body

        const createSchema = joi.object({
            code: joi.string().required().messages({
                'string.empty': 'Code must be a string',
                'any.required': 'Code is required'
            }),
            name: joi.string().required().messages({
                'string.empty': 'Name is required',
                'any.required': 'Name is required'
            }),
            classify: joi.string().required().messages({
                'string.empty': 'Classify is required',
                'any.required': 'Classify is required'
            }),
            description: joi.string().required().messages({
                'string.empty': 'Description is required',
                'any.required': 'Description is required'
            }),
            unit: joi.string().required().messages({
                'string.empty': 'Unit is required',
                'any.required': 'Unit is required'
            }),
            price: joi.number().required().messages({
                'number.base': 'Price must be a number',
                'any.required': 'Price is required'
            }),
            discount: joi.number().required().messages({
                'number.base': 'Discount must be a number',
                'any.required': 'Discount is required'
            })
        });

        const { error } = createSchema.validate({ code, name, classify, description, unit, price, discount }, { abortEarly: false });
        if (error) {
            return res.status(400).json({
                error: error.details.map(e => e.message)
            });
        }

        const result = await Menu.create({ code, name, classify, description, unit, price, discount });
        return res.status(200).json({
            ...result.toObject(),
            createdAt: formatCreatedAt(result.createdAt)
        });
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}
export const editMenu = async (req, res) => {
    try {
        const { code, name, classify, description, unit, price, discount } = req.body
        const { id } = req.params
        const editSchema = joi.object({
            code: joi.string().required().messages({
                'string.empty': 'Code must be a string',
                'any.required': 'Code is required'
            }),
            name: joi.string().required().messages({
                'string.empty': 'Name is required',
                'any.required': 'Name is required'
            }),
            classify: joi.string().required().messages({
                'string.empty': 'Classify is required',
                'any.required': 'Classify is required'
            }),
            description: joi.string().required().messages({
                'string.empty': 'Description is required',
                'any.required': 'Description is required'
            }),
            unit: joi.string().required().messages({
                'string.empty': 'Unit is required',
                'any.required': 'Unit is required'
            }),
            price: joi.number().required().messages({
                'number.base': 'Price must be a number',
                'any.required': 'Price is required'
            }),
            discount: joi.number().required().messages({
                'number.base': 'Discount must be a number',
                'any.required': 'Discount is required'
            })
        });
        const { error } = editSchema.validate({ code, name, classify, description, unit, price, discount });
        if (error) {
            return res.status(400).json({
                error: error.details.map(e => e.message)
            });
        }

        const updateMenu = await Menu.findByIdAndUpdate(id, { code, name, classify, description, unit, price, discount }, { new: true })

        return res.status(200).json({
            message: "Update successfull",
            menu: {
                ...updateMenu.toObject(),
                createdAt: formatCreatedAt(updateMenu.createdAt)
            }
        })
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}