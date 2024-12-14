import React from 'react'


export async function generateMetadata(props) {
    return {
      title: "404 Not found",
      description: "Full stack web developer",
      openGraph: {
        type: "website",
        url: "l",
        title: "My Website",
        description: "My Website Description",
        siteName: "My Website",
        images: [
          {
            url: "https://example.com/og.png",
          },
        ],
      },
    };
  }


const NotFound = () => {
  return (
    <div className="text-center m-auto min-h-screen  flex items-center justify-center flex-col ">
      <p className="text-base font-semibold text-gray-600">404</p>
      <h1 className="mt-4 text-3xl font-bold tracking-tight text-gray-900 sm:text-5xl">Page not found</h1>
      <p className="mt-6 text-base leading-7 text-gray-600">Sorry, we couldn’t find the page you’re looking for.</p>
      <div className="mt-10 flex items-center justify-center gap-x-6">
        <a
          href="/"
          className="rounded-md bg-gray-600 px-3.5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-gray-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
        >
          Go back home
        </a>
        <a href="/contact" className="text-sm font-semibold text-gray-900">
          Contact me <span aria-hidden="true">&rarr;</span>
        </a>
      </div>
    </div>
  )
}

export default NotFound   