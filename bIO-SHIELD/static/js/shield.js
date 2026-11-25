(function () {
  'use strict';

  function onReady(callback) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', callback, { once: true });
    } else {
      callback();
    }
  }

  function init() {
    var canvas = document.getElementById('shield-scene');
    if (!canvas) return;
    var frame = canvas.parentElement;

    function useFallback() {
      if (frame) frame.classList.add('is-fallback');
      canvas.hidden = true;
    }

    if (typeof window.THREE === 'undefined') {
      useFallback();
      return;
    }

    var THREE = window.THREE;
    var renderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: true, powerPreference: 'low-power' });
    } catch (error) {
      useFallback();
      return;
    }

    var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var width = Math.max(frame ? frame.clientWidth : canvas.clientWidth, 1);
    var height = Math.max(frame ? frame.clientHeight : canvas.clientHeight, 1);

    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height, false);
    renderer.setClearColor(0x000000, 0);

    var scene = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(38, width / height, 0.1, 100);
    camera.position.set(0, 0, 6.2);

    var group = new THREE.Group();
    scene.add(group);

    var shape = new THREE.Shape();
    shape.moveTo(0, 1.72);
    shape.lineTo(1.24, 1.22);
    shape.lineTo(1.18, -0.42);
    shape.quadraticCurveTo(1.04, -1.28, 0, -1.86);
    shape.quadraticCurveTo(-1.04, -1.28, -1.18, -0.42);
    shape.lineTo(-1.24, 1.22);
    shape.closePath();

    var geometry = new THREE.ExtrudeGeometry(shape, {
      depth: 0.24,
      bevelEnabled: true,
      bevelThickness: 0.08,
      bevelSize: 0.08,
      bevelSegments: 3,
      curveSegments: 18
    });
    geometry.center();

    var material = new THREE.MeshStandardMaterial({
      color: 0x1b2740,
      metalness: 0.86,
      roughness: 0.26,
      emissive: 0x070b16,
      emissiveIntensity: 0.4
    });
    var shield = new THREE.Mesh(geometry, material);
    group.add(shield);

    var edgeGeometry = new THREE.EdgesGeometry(geometry, 24);
    var edgeMaterial = new THREE.LineBasicMaterial({ color: 0xdfbe6d, transparent: true, opacity: 0.72 });
    var edges = new THREE.LineSegments(edgeGeometry, edgeMaterial);
    group.add(edges);

    var emblemGeometry = new THREE.RingGeometry(0.42, 0.47, 64);
    var emblemMaterial = new THREE.MeshBasicMaterial({ color: 0xdfbe6d, transparent: true, opacity: 0.78, side: THREE.DoubleSide });
    var emblem = new THREE.Mesh(emblemGeometry, emblemMaterial);
    emblem.position.z = 0.24;
    group.add(emblem);

    var crossMaterial = new THREE.MeshBasicMaterial({ color: 0xf0d99b, transparent: true, opacity: 0.9 });
    var verticalGeometry = new THREE.BoxGeometry(0.12, 0.56, 0.03);
    var horizontalGeometry = new THREE.BoxGeometry(0.56, 0.12, 0.03);
    var vertical = new THREE.Mesh(verticalGeometry, crossMaterial);
    var horizontal = new THREE.Mesh(horizontalGeometry, crossMaterial);
    vertical.position.z = 0.25;
    horizontal.position.z = 0.25;
    group.add(vertical);
    group.add(horizontal);

    var particleCount = 180;
    var positions = new Float32Array(particleCount * 3);
    for (var index = 0; index < particleCount; index += 1) {
      var radius = 2.1 + Math.random() * 1.6;
      var theta = Math.random() * Math.PI * 2;
      var phi = Math.acos(2 * Math.random() - 1);
      positions[index * 3] = radius * Math.sin(phi) * Math.cos(theta);
      positions[index * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
      positions[index * 3 + 2] = radius * Math.cos(phi) * 0.6;
    }
    var particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    var particleMaterial = new THREE.PointsMaterial({ color: 0xdfbe6d, size: 0.028, transparent: true, opacity: 0.55, sizeAttenuation: true });
    var particles = new THREE.Points(particleGeometry, particleMaterial);
    scene.add(particles);

    var rings = [];
    for (var ringIndex = 0; ringIndex < 3; ringIndex += 1) {
      var ringGeometry = new THREE.TorusGeometry(1.5 + ringIndex * 0.22, 0.008, 8, 120);
      var ringMaterial = new THREE.MeshBasicMaterial({ color: ringIndex === 1 ? 0x62d8b4 : 0xdfbe6d, transparent: true, opacity: 0.22, depthWrite: false });
      var ring = new THREE.Mesh(ringGeometry, ringMaterial);
      ring.position.z = -0.5;
      scene.add(ring);
      rings.push(ring);
    }

    scene.add(new THREE.AmbientLight(0xffffff, 0.42));
    var keyLight = new THREE.DirectionalLight(0xffe6b0, 1.25);
    keyLight.position.set(3, 4, 5);
    scene.add(keyLight);
    var fillLight = new THREE.PointLight(0x62d8b4, 0.8, 14);
    fillLight.position.set(-3, -2, 3);
    scene.add(fillLight);

    var intro = { progress: reduced ? 1 : 0 };
    if (!reduced && typeof window.gsap !== 'undefined') {
      window.gsap.to(intro, { progress: 1, duration: 1.7, ease: 'power3.out' });
      window.gsap.from(camera.position, { z: 9.5, duration: 1.9, ease: 'power2.out' });
    } else {
      intro.progress = 1;
      camera.position.z = 6.2;
    }

    var clock = new THREE.Clock();
    var frameId = null;

    function renderFrame() {
      var elapsed = clock.getElapsedTime();
      group.rotation.y = (1 - intro.progress) * -1.1 + Math.sin(elapsed * 0.32) * 0.32 * intro.progress;
      group.rotation.x = Math.sin(elapsed * 0.21) * 0.1 * intro.progress;
      group.scale.setScalar(0.62 + intro.progress * 0.38);
      particles.rotation.y = elapsed * 0.035;
      particles.rotation.z = Math.sin(elapsed * 0.12) * 0.08;

      rings.forEach(function (ring, index) {
        var phase = (elapsed * 0.22 + index / rings.length) % 1;
        var scale = 0.85 + phase * 0.85;
        ring.scale.setScalar(scale);
        ring.material.opacity = (1 - phase) * 0.26;
      });

      renderer.render(scene, camera);
      if (!reduced && !document.hidden) frameId = window.requestAnimationFrame(renderFrame);
    }

    function resize() {
      var nextWidth = Math.max(frame ? frame.clientWidth : canvas.clientWidth, 1);
      var nextHeight = Math.max(frame ? frame.clientHeight : canvas.clientHeight, 1);
      camera.aspect = nextWidth / nextHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(nextWidth, nextHeight, false);
      if (reduced) renderer.render(scene, camera);
    }

    window.addEventListener('resize', resize);
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        if (frameId) window.cancelAnimationFrame(frameId);
        frameId = null;
      } else if (!reduced && frameId === null) {
        clock.getDelta();
        renderFrame();
      }
    });
    window.addEventListener('pagehide', function () {
      if (frameId) window.cancelAnimationFrame(frameId);
      geometry.dispose();
      material.dispose();
      edgeGeometry.dispose();
      edgeMaterial.dispose();
      emblemGeometry.dispose();
      emblemMaterial.dispose();
      verticalGeometry.dispose();
      horizontalGeometry.dispose();
      crossMaterial.dispose();
      particleGeometry.dispose();
      particleMaterial.dispose();
      rings.forEach(function (ring) {
        ring.geometry.dispose();
        ring.material.dispose();
      });
      renderer.dispose();
    });

    renderFrame();
  }

  onReady(init);
})();
