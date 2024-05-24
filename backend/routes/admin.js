import express from "express"
import { login, createAdmin, editAdmin, getAdminById, changePassword } from "../controllers/admin.js"

const router = express.Router()
router.post("/login", login)
router.post("/create-admin", createAdmin)
router.put("/:id", editAdmin)
router.get("/:id", getAdminById)
router.put("/change-password/:id", changePassword)
export default router