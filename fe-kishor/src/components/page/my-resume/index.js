import React from "react";
import {
  EducationCard,
  ExperianceCard,
  ProjectCard,
  Resumeheading,
} from "./components";
import { resumeData } from "@/helper/data";

const ResumeIndex = () => {
  return (
    <div className="mx-auto w-full max-w-4xl  bg-white p-5  print:bg-white">
      <div>
        <Resumeheading data={resumeData} />
      </div>
      <div className="my-3">
        <h2 className="text-xl font-bold">About</h2>
        <p className="text-pretty font-mono text-sm text-muted-foreground">
          As a Full Stack Engineer, I have successfully taken multiple products
          from 0 to 1. I lead teams effectively, ensuring an environment where
          people can do their best work. Currently, I work mostly with
          TypeScript, React, Node.js, and GraphQL. I have over 8 years of
          experience in working remotely with companies all around the world.
        </p>
      </div>
      <div className="my-3">
        <h2 className="text-xl font-bold">Work Experience</h2>
        <div className=" grid grid-cols-1 gap-y-3">
          {resumeData.work.map((item, index) => (
            <ExperianceCard data={item} key={index} />
          ))}
        </div>
      </div>
      <div className="flex min-h-0 flex-col gap-y-3 my-3">
        <h2 className="text-xl font-bold">Skills</h2>
        <div>
          <ul className="flex flex-wrap gap-1">
            {resumeData.skills.map((item, index) => (
              <li
                key={index}
                className="inline-flex text-gray-50 cursor-pointer items-center rounded-md border px-2 py-0.5 text-xs font-semibold font-mono transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 text-nowrap border-transparent bg-gray-600 text-primary-foreground hover:bg-gray-800"
              >
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <div className="flex min-h-0 flex-col gap-y-3">
        <h2 className="text-xl font-bold">Education</h2>
        <div className=" grid grid-cols-1 gap-y-3">
          {resumeData.education.map((item, index) => (
            <EducationCard data={item} key={index} />
          ))}
        </div>
      </div>
      <div className="flex min-h-0 flex-col gap-y-3 print-force-new-page scroll-mb-16">
        <h2 className="text-xl font-bold">Projects</h2>
        <div className="-mx-3 grid grid-cols-1 gap-3 print:grid-cols-3 print:gap-2 md:grid-cols-2 lg:grid-cols-3">
          {resumeData.projects.map((item, index) => (
            <ProjectCard data={item} key={index} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default ResumeIndex;
