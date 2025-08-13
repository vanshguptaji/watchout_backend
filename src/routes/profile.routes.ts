import { Router } from "express";
import { updateProfilePhoto } from "../controllers/profile.controllers";
import { verifyJWT } from "../middlewares/auth.middlewares";
import upload from "../middlewares/upload.middlewares";

const router = Router();

router.patch(
  "/photo",
  verifyJWT,
  upload.single("avatar"),
  (req, res, next) => {
    updateProfilePhoto(req, res).catch(next);
  }
);

export default router;