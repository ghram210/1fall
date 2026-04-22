import { Router, type IRouter } from "express";
import healthRouter from "./health";
import invitationsRouter from "./invitations";
import adminRouter from "./admin";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/invitations", invitationsRouter);
router.use("/admin", adminRouter);

export default router;
