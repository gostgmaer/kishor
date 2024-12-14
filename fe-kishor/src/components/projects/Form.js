"use client"
import React, { useState } from "react";
import ImageUpload from "../global/fields/ImageUpload";
import MultiImageUploadr from "../global/fields/multiImageUploadr";
import TaxonomyField from "../global/fields/Taxanomy";
import { patch, post } from "@/lib/http";
import Interest from "./repeatable";
import { arrayGroupbykey } from "@/helper/function";
import { ErrorMessage, Field, FieldArray, Formik, useFormik } from "formik";
import { initialProjectValues } from "@/util/initialsvalue";

const Form = ({ }) => {
    // const [selectedFiles, setSelectedFiles] = useState(id ? id.images : []);
    // const [interests, setInterests] = useState([]);
    // const [tags, setTags] = useState(id ? id.tags : []);
    // const [imagePreview, setImagePreview] = useState(id ? id.main_image : "");
    //   const [modal, setModal] = useState(false);
    //   const [formData, setFormData] = useState({
    //     descriptions: id?.descriptions,
    //     overview: id?.overview,
    //     title: id?.name,
    //     role: id?.role,
    //     inspiration: id?.inspiration,
    //     start_date: id?.start_date,
    //     end_date: id?.end_date,
    //     current: id?.current,
    //   });

    //   const handleChange = (e) => {
    //     const { name, value } = e.target;
    //     setFormData({ ...formData, [name]: value });
    //   };

    //   const handleSaveProjects = async (body) => {
    //     try {
    //       const request = await post(
    //         `/projects`,
    //         body
    //       );
    //       if (request.statusCode === 201) {
    //         setId(undefined);
    //         setOpen(false);
    //         setIsnew(request);
    //         loadprojects()
    //       }

    //     } catch (error) {
    //       setIserror(error);
    //     }
    //     setModal(true);
    //   };

    //   const handleSave = (e) => {
    //     e.preventDefault();
    //     const technology = arrayGroupbykey(interests, "category");
    //     console.log(technology);
    //     const body = {
    //       ...formData,
    //       main_image: imagePreview,
    //       images: selectedFiles,
    //       tags: tags,
    //       technologies: technology,
    //     };

    //     handleSaveProjects(body);
    //   };

    //   const handleUpdate = async () => {
    //     const body = {
    //       ...formData,
    //       main_image: imagePreview,
    //       images: selectedFiles,
    //       tags: tags,
    //     };
    //     try {
    //       const res = await patch(
    //         `/projects`,
    //         body,
    //         id._id
    //       );
    //       setId(undefined);
    //       setOpen(false);
    //       setIsUpdate(res);
    //       loadprojects()
    //     } catch (error) {
    //       setIserror(error);
    //     }
    //     setModal(true);
    //   };


    // const formik = useFormik({
    //     initialValues: initialProjectValues,
    //     // validationSchema: 
    //     onSubmit: values => {
    //         // Handle form submission here
    //         console.log(values);
    //     },
    // });


    const handleClickData = (e, second) => {
        console.log(second);

    }


    return (
        <div className="max-w-md mx-auto">
            <Formik
                initialValues={initialProjectValues}
                onSubmit={(values, e) => {
                    handleClickData(values)

                }}
            >
                {({ values }) => (
                    <
// @ts-ignore
                    Form>
                      <FieldArray name="technologiesUsed">
                                {({ insert, remove, push }) => (
                                    <div>
                                        {values?.technologiesUsed?.length > 0 &&
                                            values?.technologiesUsed?.map((tech, index) => (
                                                <div className="row" key={index}>
                                                    <div className="col">
                                                        <label htmlFor={`technologiesUsed.${index}.name`}>Name</label>
                                                        <Field
                                                            name={`technologiesUsed.${index}.name`}
                                                            placeholder="Jane Doe"
                                                            type="text"
                                                        />

                                                    </div>

                                                    <div className="col">
                                                        <button
                                                            type="button"
                                                            className="secondary"
                                                            onClick={() => remove(index)}
                                                        >
                                                            X
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        <button
                                            type="button"
                                            className="secondary"
                                            onClick={() => push({ category: '', name: '', description: '', proficiency: '', version: '', documentationLink: '' })}
                                        >
                                            Add Friend
                                        </button>
                                    </div>
                                )}
                            </FieldArray>
                            <button type="submit" >Invite</button>
                    </Form>
                )}
            </Formik>
        </div>
    );
};

export default Form;
