"use client"

import { Disclosure, Menu, Transition } from '@headlessui/react'
import { Bars3Icon, BellIcon, XMarkIcon } from '@heroicons/react/24/outline'
import Logo from '@/components/Logo'
import { socialmedia } from '@/assets/data/mock'
import { motion } from 'framer-motion'
import Link from 'next/link'
import { useSession } from 'next-auth/react'
import { usePathname } from 'next/navigation'

const navigation = [
  // { name: 'Home', href: '/', current: true },
  { name: 'About', href: '/about', current: false },
  { name: 'Projects', href: '/portfolio', current: false },
  { name: 'Contact', href: '/contact', current: false },
]

function classNames(...classes) {
  return classes.filter(Boolean).join(' ')
}

export default function NavbarPublic() {
  const { data: session } = useSession()

  const path = usePathname()
 



  return (
    <Disclosure as="nav" className="bg-gray-600">
      {({ open }) => (
        <>
          <div className="mx-auto max-w-7xl px-2 sm:px-6 lg:px-8">
            <div className="relative flex h-20 sm:h-16 items-center justify-between w-full">
              <div className="inset-y-0 left-0 flex items-center sm:hidden">

                <Disclosure.Button className="relative inline-flex items-center justify-center rounded-md p-2 text-gray-400 hover:bg-gray-700 hover:text-white focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white">
                  <span className="absolute -inset-0.5" />
                  <span className="sr-only">Open main menu</span>
                  {open ? (
                    <XMarkIcon className="block h-6 w-6" aria-hidden="true" />
                  ) : (
                    <Bars3Icon className="block h-6 w-6" aria-hidden="true" />
                  )}
                </Disclosure.Button>
              </div>
              <div className="max-sm:hidden sm:w-full text-white font-medium flex item-center sm:justify-between relative print:hidden">
                <div className="hidden sm:ml-6 sm:block">
                  <div className="flex space-x-4">
                    <Link

                      href={'/'}
                      className={classNames(
                        path == "/" ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700 hover:text-white',
                        'rounded-md px-3 py-2 text-sm font-medium'
                      )}

                    >
                      Home
                    </Link>
                    {navigation.map((item) => (
                      <Link
                        key={item.name}
                        href={item.href}
                        className={classNames(
                          path.startsWith(item.href) ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700 hover:text-white',
                          'rounded-md px-3 py-2 text-sm font-medium'
                        )}
                        aria-current={item.current ? 'page' : undefined}
                      >
                        {item.name}
                      </Link>
                    ))}
                    {session && <Link

                      href={'/dashboard'}
                      className='text-gray-300 hover:bg-gray-700 hover:text-white rounded-md px-3 py-2 text-sm font-medium'

                    >
                      Dashboard
                    </Link>}
                  </div>
                </div>
                <div className=" sm:absolute sm:left-[50%] sm:top-2 sm:translate-x-[-50%] ">
                  <Logo />
                </div>
                <nav className="hidden items-center gap-3 sm:flex  md:flex ">
                  {socialmedia.map((social) => (
                    <motion.a key={social.id} target="_blank" href={`${social.url}`} whileHover={{ y: -2 }} whileTap={{ scale: 0.9 }}>
                      {social.icon}
                    </motion.a>
                  ))}
                  {/* {session && <Link href={'/dashboard'}>Dashboard</Link>} */}
                </nav>
              </div>

            </div>
          </div>

          <Disclosure.Panel className="sm:hidden">
            <div className="space-y-1 px-2 pb-3 pt-2">
              {navigation.map((item) => (
                <Disclosure.Button
                  key={item.name}
                  as="a"
                  href={item.href}
                  className={classNames(
                    item.current ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700 hover:text-white',
                    'block rounded-md px-3 py-2 text-base font-medium'
                  )}
                  aria-current={item.current ? 'page' : undefined}
                >
                  {item.name}
                </Disclosure.Button>
              ))}
            </div>
          </Disclosure.Panel>
        </>
      )}
    </Disclosure>
  )
}