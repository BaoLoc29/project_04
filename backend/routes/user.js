import express from "express"
import { login, createUser, editUser, deleteUser, getPagingUser, searchUser, getUserById, changePassword } from "../controllers/user.js"

const router = express.Router()
router.post("/login", login)
router.post("/create-user", createUser)
router.put("/:id", editUser)
router.delete("/:id", deleteUser)
router.get("/get-paging-user", getPagingUser)
router.get("/:id", getUserById)
router.post("/search-user", searchUser)
router.put("/change-password/:id", changePassword)
export default router