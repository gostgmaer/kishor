import React, { useState } from "react";
import ImageUpload from "../global/fields/ImageUpload";
import MultiImageUploadr from "../global/fields/multiImageUploadr";
import TaxonomyField from "../global/fields/Taxanomy";
import { patch, post } from "@/lib/http";
import Interest from "./repeatable";
import { arrayGroupbykey } from "@/helper/function";
import { useFormik } from "formik";

const ProjectForm = ({ id, setId, setOpen, loadprojects }) => {
  const [selectedFiles, setSelectedFiles] = useState(id ? id.images : []);
  const [interests, setInterests] = useState([]);
  const [tags, setTags] = useState(id ? id.tags : []);
  const [imagePreview, setImagePreview] = useState(id ? id.main_image : "");
  const [modal, setModal] = useState(false);
  const [formData, setFormData] = useState({
    descriptions: id?.descriptions,
    overview: id?.overview,
    title: id?.name,
    role: id?.role,
    inspiration: id?.inspiration,
    start_date: id?.start_date,
    end_date: id?.end_date,
    current: id?.current,
  });
  const [isUpdate, setIsUpdate] = useState(false);
  const [isnew, setIsnew] = useState(false);
  const [iserror, setIserror] = useState(undefined);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSaveProjects = async (body) => {
    try {
      const request = await post(
        `/projects`,
        body
      );
      if (request.statusCode === 201) {
        setId(undefined);
        setOpen(false);
        setIsnew(request);
        loadprojects()
      }

    } catch (error) {
      setIserror(error);
    }
    setModal(true);
  };

  const handleSave = (e) => {
    e.preventDefault();
    const technology = arrayGroupbykey(interests, "category");
    console.log(technology);
    const body = {
      ...formData,
      main_image: imagePreview,
      images: selectedFiles,
      tags: tags,
      technologies: technology,
    };

    handleSaveProjects(body);
  };

  const handleUpdate = async () => {
    const body = {
      ...formData,
      main_image: imagePreview,
      images: selectedFiles,
      tags: tags,
    };
    try {
      const res = await patch(
        `/projects`,
        body,
        id._id
      );
      setId(undefined);
      setOpen(false);
      setIsUpdate(res);
      loadprojects()
    } catch (error) {
      setIserror(error);
    }
    setModal(true);
  };


  const formik = useFormik({
    initialValues: {
      email: "",
      password: "",
    },
    // validationSchema: loginValidationSchema,
    onSubmit: async (values,{setSubmitting,resetForm}) => {
      
    },
  });




  return (
    <div className="container p-2 mx-auto sm:p-4">
      <form className=" mx-auto bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
        <h2 className="text-2xl mb-4 font-semibold">Add Project</h2>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {/* Project Name */}
          <div className="">
            <label
              htmlFor="title"
              className="block text-gray-700 text-sm font-bold mb-2"
            >
              Project Name
            </label>
            <input
              type="text"
              id="title"
              name="title"
              onChange={handleChange}
              value={formData.title}
              autoComplete="off"
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              placeholder="Basilar"
            />
          </div>

          {/* Role */}
          <div className="">
            <label
              htmlFor="role"
              className="block text-gray-700 text-sm font-bold mb-2"
            >
              Role
            </label>
            <input
              type="text"
              id="role"
              name="role"
              onChange={handleChange}
              value={formData.role}
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              placeholder="Lead Engineer Lead Developer"
            />
          </div>
          <div className="">
            <label
              htmlFor="start_date"
              className="block text-gray-700 text-sm font-bold mb-2"
            >
              Start Date
            </label>
            <input
              type="date"
              id="start_date"
              name="start_date"
              onChange={handleChange}
              value={formData.start_date}
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            />
          </div>

          <div className="">
            <label
              htmlFor="end_date"
              className="block text-gray-700 text-sm font-bold mb-2"
            >
              End Date
            </label>
            <input
              type="date"
              id="end_date"
              name="end_date"
              onChange={handleChange}
              value={formData.end_date}
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            />
          </div>

          <div className=" col-span-2">
            <ImageUpload
              imagePreview={imagePreview}
              setImagePreview={setImagePreview}
              label={"Landing Page Image"}
            ></ImageUpload>
          </div>
          <div className="col-span-2 ">
            <label
              htmlFor="overview"
              className="block text-gray-700 text-sm font-bold mb-2"
            >
              Overview
            </label>
            <textarea
              id="overview"
              name="overview"
              onChange={handleChange}
              value={formData.overview}
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline h-20"
              placeholder="Overview"
            ></textarea>
          </div>
          <div className="col-span-2">
            <TaxonomyField
              label={"Project Tags"}
              selectedTaxonomy={tags}
              setSelectedTaxonomy={setTags}
            ></TaxonomyField>
          </div>
          <div className="col-span-2">
            <label
              htmlFor="descriptions"
              className="block text-gray-700 text-sm font-bold mb-2"
            >
              Descriptions
            </label>
            <textarea
              id="descriptions"
              name="descriptions"
              onChange={handleChange}
              value={formData.descriptions}
              className="shadow appearance-none border h-32 rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              placeholder="Add project Descriptions"
            />
          </div>
        </div>

        <div>
          <MultiImageUploadr
            selectedFiles={selectedFiles}
            setSelectedFiles={setSelectedFiles}
            label={"Upload project Images"}
          />
        </div>
        <div className="">
          <Interest
            interests={interests}
            setInterestes={setInterests}
            label={"Add Technology"}
          />
        </div>
        {/* Submit Button */}
        <div className="flex items-center justify-between">
          {!id ? (
            <button
              className="bg-gray-600 hover:bg-gray-800 text-white font-bold py-2 px-4  w-32 rounded focus:outline-none focus:shadow-outline"
              type="button"
              onClick={handleSave}
            >
              Save
            </button>
          ) : (
            <button
              onClick={handleUpdate}
              className="bg-gray-600 hover:bg-gray-800 text-white font-bold py-2 w-32 px-4 rounded focus:outline-none focus:shadow-outline"
              type="button"
            >
              Update
            </button>
          )}
        </div>
      </form>
    </div>
  );
};

export default ProjectForm;
