import { tech } from "@/assets/data/projects";
import React from "react";
import {
  FaJsSquare,
  FaHtml5,
  FaCss3,
  FaReact,
  FaAngular,
  FaVuejs,
  FaBootstrap,
  FaBullhorn,
  FaNodeJs,
  FaPython,
  FaGem,
  FaDatabase,
} from "react-icons/fa";
import { IoCodeWorkingOutline } from "react-icons/io5";

const Technologies = ({}) => {
  var data = tech;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
      {data.technologies.frontendTechnologies.map((category) => (
        <div
          key={category.category}
          className="bg-white p-4 rounded-lg shadow-md hover:shadow-lg transition duration-300"
        >
          <h2 className="text-lg font-semibold mb-2">{category.category}</h2>
          {category.technologies.map((technology) => (
            <div key={technology.name} className="mb-2 flex items-center">
              <span className="mr-2 text-inherit">
                {getIcon(technology.icon)}
              </span>{" "}
              <span>{technology.name}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
};

const getIcon = (iconName) => {
  const icons = {
    FaJsSquare: <FaJsSquare />,
    FaHtml5: <FaHtml5 />,
    FaCss3: <FaCss3 />,
    FaReact: <FaReact />,
    FaAngular: <FaAngular />,
    FaVuejs: <FaVuejs />,
    FaBootstrap: <FaBootstrap />,

    FaBullhorn: <FaBullhorn />,
    FaNodeJs: <FaNodeJs />,
    FaPython: <FaPython />,
    FaGem: <FaGem />,
    FaDatabase: <FaDatabase />,
  };

  return icons[iconName] || <IoCodeWorkingOutline />;
};

export default Technologies;
