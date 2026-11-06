// The design-feedback drill (Phase 0): one catalog item in two revisions, folded from the ledger into design feedback.
export { catalogRevision, revisionId, sameRevision, successorOf, termId } from "./catalog";
export type { CatalogRevision, Method, RevisionKey } from "./catalog";
export { LIFE_BAND_WIDTH, MASS_BALANCE_TOLERANCE, POOLED, UNKNOWN_REVISION, attributeDifference, compareWithSuccessor, featurePerformance, revisionPerformance } from "./performance";
export type { Basis, BandGap, Comparison, DiversionFigure, FeatureRow, FeatureShare, Figure, JointFigure, Leakage, RevisionRow } from "./performance";
export { PROPERTY_SET, writeIfc } from "./ifc";
export type { IfcResult } from "./ifc";
export { PILOT_BANNER, renderReport } from "./report";
export { COHORT_MINIMUM, plan } from "./plan";
export type { PlanAsset, PlanBasis, PlanLine } from "./plan";
