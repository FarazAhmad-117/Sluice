import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Navigate, RouterProvider, createHashRouter } from "react-router";
import NewProjectRoute from "@/routes/new-project";
import ProjectCompareRoute from "@/routes/project-compare";
import ProjectOverviewRoute from "@/routes/project-overview";
import ProjectSecretsRoute from "@/routes/project-secrets";
import { PreviewProjects, PreviewProviders, PreviewShell } from "./preview-app";
import "../app.css";

/**
 * The entry of `preview.html`, development only. See `preview-app.tsx`.
 * Same paths as the real route table, under a hash router.
 */
const router = createHashRouter([
  {
    element: <PreviewProviders />,
    children: [
      { index: true, element: <Navigate to="/projects/storefront-api" replace /> },
      {
        element: <PreviewShell />,
        children: [
          { path: "projects", element: <PreviewProjects /> },
          { path: "projects/new", element: <NewProjectRoute /> },
          { path: "projects/:projectSlug", element: <ProjectOverviewRoute /> },
          { path: "projects/:projectSlug/secrets", element: <ProjectSecretsRoute /> },
          { path: "projects/:projectSlug/compare", element: <ProjectCompareRoute /> },
        ],
      },
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
