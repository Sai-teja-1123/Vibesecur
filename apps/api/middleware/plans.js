// ============================================================
//  Vibesecur — middleware/plans.js
// ============================================================
const PLAN_ORDER = ['free', 'solo', 'pro', 'admin'];

export const requirePlan = (minPlan) => (req, res, next) => {
  if (PLAN_ORDER.indexOf(req.user?.plan) < PLAN_ORDER.indexOf(minPlan)) {
    return res.status(403).json({
      success: false,
      error: `This feature requires the ${minPlan} plan or higher`,
      upgrade: true,
      requiredPlan: minPlan,
    });
  }
  next();
};
