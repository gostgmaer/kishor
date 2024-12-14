import requests from "./httpServices";

const ProjectsServices = {
  // Create a new project
  createProject: async (body, token) => {
    return requests.post("/projects", body, token);
  },

  // Get all projects
  getProjects: async (query, token) => {
    return requests.get("/projects", query,{}, token);
  },

  // Get a single project by ID
  getSingleProject: async (id, token) => {
    return requests.get(`/projects/${id}`,{}, {}, token);
  },

  // Update a single project by ID (PATCH method)
  updateProjectPatch: async (id, body, token) => {
    return requests.patch(`/projects/${id}`, body,{}, token);
  },

  // Update a single project by ID (PUT method)
  updateProjectPut: async (id, body, token) => {
    return requests.put(`/projects/${id}`, body, {},token);
  },

  // Remove a single project by ID
  removeProject: async (id, token) => {
    return requests.delete(`/projects/${id}`, {}, token);
  },

  // Remove multiple projects (bulk delete)
  removeManyProjects: async (body, token) => {
    return requests.deletebulk("/projects/bulk", body, token);
  },
};

export default ProjectsServices;
