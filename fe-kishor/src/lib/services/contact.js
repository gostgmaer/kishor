import requests from "./httpServices";

const ContactsServices = {
  // Create a new contact
  createContact: async (body, token) => {
    return requests.post("/contacts", body, token);
  },

  // Get all contacts
  getContacts: async (query, token) => {
    return requests.get("/contacts", query,{}, token);
  },

  // Get a single contact by ID
  getSingleContact: async (id, token) => {
    return requests.get(`/contacts/${id}`,{}, {}, token);
  },

  // Update a single contact by ID (PATCH method)
  updateContactPatch: async (id, body, token) => {
    return requests.patch(`/contacts/${id}`, body,{}, token);
  },

  // Update a single contact by ID (PUT method)
  updateContactPut: async (id, body, token) => {
    return requests.put(`/contacts/${id}`, body,{}, token);
  },

  // Remove a single contact by ID
  removeContact: async (id, token) => {
    return requests.delete(`/contacts/${id}`, {}, token);
  },

  // Remove multiple contacts (bulk delete)
  removeManyContacts: async (body, token) => {
    return requests.deletebulk("/contacts/bulk", body, token);
  },
};

export default ContactsServices;
