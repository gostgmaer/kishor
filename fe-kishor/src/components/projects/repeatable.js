import { findIndex } from "@/helper/function";
import React, { useState } from "react";
import { Select } from "../global/fields/SelectField";
import { techCate } from "@/assets/data/mock";
import Input from "../global/fields/input";

const Interest = ({ interests, setInterestes, label }) => {
  const [formData, setFormData] = useState({
    category: "",
    description: "",
    name: "",
    icon: "",
  });
  const [editIndex, setEditIndex] = useState(-1);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleAdd = () => {
    setInterestes([...interests, formData]);
    setFormData({
      category: "",
      description: "",
      name: "",
      icon: "",
    });
    console.log(interests);
  };

  const handleRemove = (index) => {
    const updatedExperiences = [...interests];
    updatedExperiences.splice(index, 1);
    setInterestes(updatedExperiences);
  };

  const handleEdit = (index) => {
    setEditIndex(index);
    const editdata = findIndex(interests, index);
    setFormData(editdata);
  };

  const handleSaveEdit = () => {
    if (editIndex !== -1) {
      const updatedData = [...interests];
      updatedData[editIndex] = formData;
      setInterestes(updatedData);
      setEditIndex(-1);
      setFormData({
        category: "",
        description: "",
        name: "",
        icon: "",
      });
    }
  };

  return (
    <div className="w-full max-w-screen-xl mx-auto">
      <h3 className="text-xl font-semibold my-2">{label}</h3>
      <div className="w-full max-w-screen-xl mx-auto mb-4">
        <form className="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="">
           
              <Select
                label={"Category"}
                id={"category"}
                options={techCate}
                optionkeys={{ key: "id", value: "name" }}
                placeholder={undefined}
                additionalAttrs={{ onChange: handleChange, value: formData.category }}
              />
            </div>

            <div className="">
              <Input label={"Name"} type={"text"}   additionalAttrs={{ onChange: handleChange, value: formData.name }} classes={undefined} icon={undefined} id={"name"}/>
             
            </div>

            <div className=" col-span-2 grid grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <button
                  className="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                  type="button"
                  onClick={() => {
                    setFormData({
                      category: "",
                      description: "",
                      name: "",
                      icon: "",
                    });
                  }}
                >
                  Clear
                </button>
              </div>
              <div className="mb-6 text-right">
                {editIndex === -1 ? (
                  <button
                    className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                    type="button"
                    onClick={handleAdd}
                  >
                    Add
                  </button>
                ) : (
                  <button
                    className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                    type="button"
                    onClick={handleSaveEdit}
                  >
                    Update
                  </button>
                )}
              </div>
            </div>
          </div>
        </form>
        <div className="flex flex-wrap">
          {interests.map((project, index) => (
            <InterestCard
              key={index}
              {...project}
              onEdit={() => handleEdit(index)}
              onDelete={() => handleRemove(index)}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

export default Interest;

const InterestCard = ({ name, onEdit, onDelete }) => {
  return (
    <div className="bg-white shadow-lg rounded-lg overflow-hidden m-4 p-4">
      <div className="mb-4">
        <h4 className="text-md font-semibold">{name}</h4>
      </div>
      <div className="mt-auto">
        <div className="flex justify-between">
          <button
            onClick={() => onEdit()}
            className="bg-blue-500 text-white px-1 rounded hover:bg-blue-600 transition duration-300 ease-in-out transform hover:scale-105"
          >
            Edit
          </button>
          <button
            onClick={() => onDelete()}
            className="bg-red-500 text-white px-1  rounded hover:bg-red-600 transition duration-300 ease-in-out transform hover:scale-105 ml-2"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
};
