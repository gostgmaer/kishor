"use client"
import { useRouter } from 'next/navigation';
import React from 'react'

const DownloadResume = () => {
  const route = useRouter()

  function downloadFile() {
    var link = document.createElement('a');
    link.href = "./assets/file/kishor.pdf";
    link.download = "Kishor.pdf";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
      }
  
    const handlePrint = () => {
      window.print();
    };
  

  return (
    <div className="action-btn print:hidden my-2 flex w-full items-center justify-between">
      <div className=''>

      <button
        onClick={()=>{
          route.back()
        }}
        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mr-2"
      >
        Back
      </button>

      </div>
    <div className=" ">
      <button
        onClick={downloadFile}
        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mr-2"
      >
        Download
      </button>
      <button
        onClick={handlePrint}
        className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
      >
        Print
      </button>
    </div>
    </div>
  )
}

export default DownloadResume


