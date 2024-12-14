"use client";
import ImageUpload from "@/components/global/fields/ImageUpload";
import { useAuthContext } from "@/contex/authContext";
import { patch } from "@/lib/http";

import Image from "next/image";
import { useRouter } from "next/navigation";
import React, { useEffect, useState } from "react";
import { MdClose } from "react-icons/md";

const Personal = (props) => {


  const profileInfo = props.data
  const [close, setClose] = useState(true);
  return (
    <div className="container mx-auto py-8 text-black">
      <div className=" flex justify-between items-center my-5">
        <h1 className="text-3xl font-semibold mb-4">My Profile</h1>
        {profileInfo?.result?.profilePicture && (
          <Image
            width={100}
            height={100}
            property="false"
            src={profileInfo.result.profilePicture}
            style={{ borderRadius: "50%", height: "100px" }}
            alt=""
            className=""
          />
        )}
      </div>
      {profileInfo && (
        <UserprofileDetails userData={profileInfo.result} setClose={setClose} />
      )}
      {!close && (
        <UserProfile
          data={profileInfo.result}
          setClose={setClose}
        />
      )}
    </div>
  );
};

export default Personal;

const UserProfile = ({ data, setClose }) => {
  const [formData, setFormData] = useState({
    firstName: data?.firstName,
    lastName: data.lastName,
    profilePicture: data?.profilePicture,
    contactNumber: data?.contactNumber,
    resume:data?.resume
  });
const router = useRouter()
  const [imagePreview, setimagePreview] = useState(data?.profilePicture);
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const UpdateProfile = async (e) => {
    e.preventDefault();
    const recordData = {
      ...formData,
      profilePicture: imagePreview,
    };

    try {
      const res = await patch(`/authentication/user/current/profile/update`, recordData, data["_id"]);
      if (res.statusCode ===200) {
        router.push('/dashboard/profile')
        setClose(true);
      } else {
      }
    } catch (error) {}
  };



  return (
    <form className="bg-gray-50 p-4 rounded-lg shadow-md">
      <div className=" flex justify-between items-center">
        {" "}
        <h2 className="text-2xl font-semibold mb-4">Basic Info</h2>{" "}
        <button className="text-red-500 hover:text-red-700 cursor-pointer">
          <MdClose size={24} onClick={() => setClose(true)} />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label
            htmlFor="firstName"
            className="block text-gray-600 font-semibold mb-2"
          >
            First Name:
          </label>
          <input
            type="text"
            name="firstName"
            id="firstName"
            className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring focus:border-blue-500"
            value={formData.firstName}
            onChange={handleChange}
          />
        </div>

        <div>
          <label
            htmlFor="lastName"
            className="block text-gray-600 font-semibold mb-2"
          >
            Last Name:
          </label>
          <input
            type="text"
            name="lastName"
            id="lastName"
            className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring focus:border-blue-500"
            value={formData.lastName}
            onChange={handleChange}
          />
        </div>

        <div>
          <label
            htmlFor="contactNumber"
            className="block text-gray-600 font-semibold mb-2"
          >
            Phone Number:
          </label>
          <input
            type="text"
            name="contactNumber"
            id="contactNumber"
            className="w-full  read-only:bg-slate-100 px-3 py-2 border rounded-md focus:outline-none focus:ring focus:border-blue-500"
            value={formData.contactNumber}
            onChange={handleChange}
          />
        </div>

        <div>
          <ImageUpload
            imagePreview={imagePreview}
            setImagePreview={setimagePreview} label={"profile Picture"}          />
        </div>
        <div>
          <label
            htmlFor="resume_id"
            className="block text-gray-600 font-semibold mb-2"
          >
            Resume ID:
          </label>
          <input
            type="text"
            name="resume_id"
            id="resume_id"
            className="w-full  read-only:bg-slate-100 px-3 py-2 border rounded-md focus:outline-none focus:ring focus:border-blue-500"
            value={formData.resume}
            onChange={handleChange}
          />
        </div>
       

      
      </div>
      <div className="col-span-1 mt-4 flex justify-end">
        <button
          type="button"
          onClick={UpdateProfile}
          className="bg-blue-500 text-white py-2 disabled:bg-blue-200 disabled:pointer-events-none px-4 rounded hover:bg-blue-600 focus:outline-none focus:ring focus:border-blue-300"
        >
          Save Details
        </button>
      </div>
    </form>
  );
};

const UserprofileDetails = ({ userData, setClose }) => {
  return (
    <div className="bg-gray-50 p-4 rounded-lg shadow-md mb-10">
      <div className="grid grid-cols-2 gap-4">
        <div className="">
          <label className="text-gray-700 font-bold mb-2" htmlFor="firstName">
            First Name:
          </label>
          <span className="text-gray-800">{userData.firstName}</span>
        </div>

        <div className="">
          <label className="text-gray-700 font-bold mb-2" htmlFor="lastName">
            Last Name:
          </label>
          <span className="text-gray-800">{userData.lastName}</span>
        </div>

        <div>
          <label className="text-gray-700 font-bold mb-2" htmlFor="username">
            Username:
          </label>
          <span className="text-gray-800">{userData.username}</span>
        </div>

        <div>
          <label className="text-gray-700 font-bold mb-2" htmlFor="email">
            Email:
          </label>
          <span className="text-gray-800">{userData.email}</span>
        </div>

        <div>
          <label className="text-gray-700 font-bold mb-2" htmlFor="role">
            Role:
          </label>
          <span className="text-gray-800">{userData.role}</span>
        </div>

      { userData.resume && <div className=" col-span-full">
          <label className="text-gray-700 font-bold mb-2" htmlFor="resume">
            Resume Id:
          </label>
          <span className="text-gray-800">{userData.resume}</span>
        </div>
       }

        <div className=" col-span-2 flex justify-end">
          <button
            type="button"
            onClick={() => setClose(false)}
            className="bg-blue-500 text-white py-2 px-4 rounded hover:bg-blue-600 focus:outline-none focus:ring focus:border-blue-300"
          >
            Update Information
          </button>
        </div>
      </div>
    </div>
  );
};
