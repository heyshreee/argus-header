import Nav from './components/Nav';
import Hero from './components/Hero';
import Product from './components/Product';
import Checks from './components/Checks';
import Analysis from './components/Analysis';
import Cli from './components/Cli';
import Workflow from './components/Workflow';
import Engine from './components/Engine';
import OpenSource from './components/OpenSource';
import Install from './components/Install';
import Cta from './components/Cta';
import Footer from './components/Footer';
import { useReveal } from './lib/useReveal';

export default function App() {
  useReveal();

  return (
    <>
      <a className="skip-link" href="#main">
        SKIP TO CONTENT
      </a>
      <Nav />
      <main id="main">
        <Hero />
        <Product />
        <Checks />
        <Analysis />
        <Cli />
        <Workflow />
        <Engine />
        <OpenSource />
        <Install />
        <Cta />
      </main>
      <Footer />
    </>
  );
}