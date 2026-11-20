// PFCentral login scene (three.js): the PFCentral shield spins at the centre of a network.
// Traffic flows in from the edge; cyan packets pass the firewall ring, red ones are stopped at it.
import * as THREE from '/vendor/three/three.module.min.js';

const canvas = document.getElementById('pfc-scene');
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function webglAvailable() {
    try {
        const c = document.createElement('canvas');
        return !!(window.WebGLRenderingContext && (c.getContext('webgl2') || c.getContext('webgl')));
    } catch (e) {
        return false;
    }
}

if (canvas && webglAvailable()) {
    start();
} else {
    document.documentElement.classList.add('pfc-no-webgl');
}

function start() {
    const CYAN = new THREE.Color('#33C5F3');
    const ICE = new THREE.Color('#E6F7FD');
    const RED = new THREE.Color('#FF5A64');
    const NAVY = new THREE.Color('#0E2238');

    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: 'low-power' });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;

    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(NAVY, 14, 30);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
    camera.position.set(0, 0.6, 16);

    scene.add(new THREE.AmbientLight(0x9fdcff, 0.55));
    const key = new THREE.DirectionalLight(0xffffff, 1.6);
    key.position.set(4, 6, 8);
    scene.add(key);
    const rim = new THREE.DirectionalLight(0x33c5f3, 1.4);
    rim.position.set(-6, -2, -4);
    scene.add(rim);
    const core = new THREE.PointLight(0x33c5f3, 18, 9, 1.6);
    core.position.set(0, 0, 2.2);
    scene.add(core);

    // World root: shifted left on wide screens so the sign-in panel never covers the logo.
    const world = new THREE.Group();
    scene.add(world);

    /* ------------------------------------------------------------ the logo */
    const logo = new THREE.Group();
    world.add(logo);

    // Shield outline traced from the PFCentral mark (64x64 SVG, centred and scaled).
    const s = 0.085;
    const P = (x, y) => new THREE.Vector2((x - 32) * s, (32 - y) * s);
    const shield = new THREE.Shape();
    const a = P(32, 4), b = P(56, 12.5), c = P(56, 30), d = P(32, 60), e = P(8, 30), f = P(8, 12.5);
    shield.moveTo(a.x, a.y);
    shield.lineTo(b.x, b.y);
    shield.lineTo(c.x, c.y);
    const c1 = P(56, 45.2), c2 = P(45.7, 55.6), c3 = P(18.3, 55.6), c4 = P(8, 45.2);
    shield.bezierCurveTo(c1.x, c1.y, c2.x, c2.y, d.x, d.y);
    shield.bezierCurveTo(c3.x, c3.y, c4.x, c4.y, e.x, e.y);
    shield.lineTo(f.x, f.y);
    shield.closePath();

    const shieldGeo = new THREE.ExtrudeGeometry(shield, {
        depth: 0.55, bevelEnabled: true, bevelThickness: 0.14, bevelSize: 0.12, bevelSegments: 4, curveSegments: 32,
    });
    shieldGeo.center();
    const shieldMesh = new THREE.Mesh(shieldGeo, new THREE.MeshStandardMaterial({
        color: 0x12385a, metalness: 0.55, roughness: 0.32, emissive: 0x0a1c30, emissiveIntensity: 0.6,
    }));
    logo.add(shieldMesh);

    // Cyan rim around the front and back faces.
    const outlinePts = shield.getPoints(96).map((p) => new THREE.Vector3(p.x, p.y, 0));
    const outlineCenter = new THREE.Box3().setFromPoints(outlinePts).getCenter(new THREE.Vector3());
    const rimGeo = new THREE.BufferGeometry().setFromPoints(outlinePts.map((p) => p.sub(outlineCenter)));
    const rimMat = new THREE.LineBasicMaterial({ color: CYAN, transparent: true, opacity: 0.95 });
    const frontRim = new THREE.LineLoop(rimGeo, rimMat);
    frontRim.position.z = 0.42;
    frontRim.scale.setScalar(1.035);
    logo.add(frontRim);
    const backRim = frontRim.clone();
    backRim.position.z = -0.42;
    logo.add(backRim);

    // Hub and spokes on both faces (so the mark reads from either side while it spins).
    const hubMat = new THREE.MeshStandardMaterial({ color: CYAN, emissive: CYAN, emissiveIntensity: 0.9, metalness: 0.2, roughness: 0.3 });
    const nodeMat = new THREE.MeshStandardMaterial({ color: ICE, emissive: 0x7fd9f7, emissiveIntensity: 0.35, roughness: 0.4 });
    const spokeMat = new THREE.MeshStandardMaterial({ color: CYAN, emissive: CYAN, emissiveIntensity: 0.6 });
    const hubCenter = P(32, 32).sub(new THREE.Vector2(outlineCenter.x, outlineCenter.y));
    const nodes2d = [P(32, 16.5), P(18.6, 40.2), P(45.4, 40.2)].map((v) => v.sub(new THREE.Vector2(outlineCenter.x, outlineCenter.y)));
    for (const side of [1, -1]) {
        const z = side * 0.44;
        const hub = new THREE.Mesh(new THREE.SphereGeometry(0.5, 32, 16), hubMat);
        hub.position.set(hubCenter.x, hubCenter.y, z);
        hub.scale.z = 0.45;
        logo.add(hub);
        for (const n of nodes2d) {
            const node = new THREE.Mesh(new THREE.SphereGeometry(0.3, 24, 12), nodeMat);
            node.position.set(n.x, n.y, z);
            node.scale.z = 0.5;
            logo.add(node);
            const from = new THREE.Vector3(hubCenter.x, hubCenter.y, z);
            const to = new THREE.Vector3(n.x, n.y, z);
            const len = from.distanceTo(to);
            const spoke = new THREE.Mesh(new THREE.CylinderGeometry(0.07, 0.07, len, 10), spokeMat);
            spoke.position.copy(from).lerp(to, 0.5);
            spoke.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), to.clone().sub(from).normalize());
            logo.add(spoke);
        }
    }

    /* ------------------------------------------------------ firewall rings */
    const RING_R = 3.9;
    const ringMat = new THREE.MeshBasicMaterial({ color: CYAN, transparent: true, opacity: 0.55 });
    const ring = new THREE.Mesh(new THREE.TorusGeometry(RING_R, 0.025, 8, 180), ringMat);
    ring.rotation.x = Math.PI / 2.35;
    world.add(ring);
    const ring2 = new THREE.Mesh(new THREE.TorusGeometry(RING_R + 0.35, 0.012, 6, 180),
        new THREE.MeshBasicMaterial({ color: CYAN, transparent: true, opacity: 0.22 }));
    ring2.rotation.set(Math.PI / 2.1, 0.35, 0);
    world.add(ring2);

    // Faint shield sphere: where packets are inspected.
    const dome = new THREE.Mesh(new THREE.SphereGeometry(RING_R, 48, 24),
        new THREE.MeshBasicMaterial({ color: CYAN, transparent: true, opacity: 0.035, depthWrite: false }));
    world.add(dome);

    /* ------------------------------------------------------- outer network */
    const small = window.innerWidth < 768;
    const NODE_COUNT = small ? 26 : 44;
    const nodes = [];
    const net = new THREE.Group();
    world.add(net);
    const netNodeGeo = new THREE.SphereGeometry(0.065, 12, 8);
    const netNodeMat = new THREE.MeshBasicMaterial({ color: 0x8fdcf8, transparent: true, opacity: 0.85 });
    for (let i = 0; i < NODE_COUNT; i++) {
        // Even spread on a shell (golden spiral), slightly jittered.
        const t = (i + 0.5) / NODE_COUNT;
        const inc = Math.acos(1 - 2 * t);
        const az = Math.PI * (1 + Math.sqrt(5)) * i;
        const r = 7.2 + Math.random() * 1.8;
        const v = new THREE.Vector3(Math.sin(inc) * Math.cos(az), Math.cos(inc) * 0.72, Math.sin(inc) * Math.sin(az) * 0.55).multiplyScalar(r);
        const m = new THREE.Mesh(netNodeGeo, netNodeMat);
        m.position.copy(v);
        net.add(m);
        nodes.push(v);
    }
    const linkPts = [];
    nodes.forEach((v, i) => {
        nodes.map((w, j) => [j, v.distanceTo(w)]).filter(([j]) => j !== i).sort((x, y) => x[1] - y[1]).slice(0, 2)
            .forEach(([j]) => { if (j > i) linkPts.push(v, nodes[j]); });
    });
    net.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(linkPts),
        new THREE.LineBasicMaterial({ color: 0x33c5f3, transparent: true, opacity: 0.16 })));

    // Dust: a soft starfield for depth.
    const dustGeo = new THREE.BufferGeometry();
    const DUST = small ? 220 : 420;
    const dust = new Float32Array(DUST * 3);
    for (let i = 0; i < DUST; i++) {
        dust[i * 3] = (Math.random() - 0.5) * 46;
        dust[i * 3 + 1] = (Math.random() - 0.5) * 26;
        dust[i * 3 + 2] = -Math.random() * 22 - 2;
    }
    dustGeo.setAttribute('position', new THREE.BufferAttribute(dust, 3));
    scene.add(new THREE.Points(dustGeo, new THREE.PointsMaterial({ color: 0x9fdcff, size: 0.05, transparent: true, opacity: 0.5 })));

    /* ------------------------------------------------------------- packets */
    const packets = [];
    const packetGeo = new THREE.SphereGeometry(0.095, 10, 8);
    const bursts = [];
    const burstGeo = new THREE.RingGeometry(0.05, 0.12, 24);

    function spawnPacket() {
        const from = nodes[Math.floor(Math.random() * nodes.length)];
        const threat = Math.random() < 0.3;
        const mat = new THREE.MeshBasicMaterial({ color: threat ? RED : CYAN, transparent: true, opacity: 0 });
        const mesh = new THREE.Mesh(packetGeo, mat);
        mesh.position.copy(from);
        net.add(mesh);
        // Trail
        const trailGeo = new THREE.BufferGeometry().setFromPoints([from.clone(), from.clone()]);
        const trail = new THREE.Line(trailGeo, new THREE.LineBasicMaterial({ color: threat ? RED : CYAN, transparent: true, opacity: 0 }));
        net.add(trail);
        packets.push({ mesh, trail, from: from.clone(), threat, t: 0, speed: 0.16 + Math.random() * 0.12 });
    }

    function burst(position) {
        const m = new THREE.Mesh(burstGeo, new THREE.MeshBasicMaterial({ color: RED, transparent: true, opacity: 0.9, side: THREE.DoubleSide, depthWrite: false }));
        m.position.copy(position);
        m.lookAt(camera.position);
        net.add(m);
        bursts.push({ m, t: 0 });
        ring.material.opacity = 0.95; // the ring flashes when it stops something
    }

    /* -------------------------------------------------------------- layout */
    let offsetX = 0;
    function resize() {
        const w = canvas.clientWidth || window.innerWidth;
        const h = canvas.clientHeight || window.innerHeight;
        renderer.setSize(w, h, false);
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        // Visible width at z = 0, then move the scene into the free area left of the panel.
        const visibleW = 2 * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) * camera.position.z * camera.aspect;
        const visibleH = visibleW / camera.aspect;
        offsetX = w >= 1024 ? -visibleW * 0.2 : 0;
        world.position.x = offsetX;
        // Narrow screens: smaller, in the space above the sign-in panel.
        world.scale.setScalar(w >= 1024 ? 1 : THREE.MathUtils.clamp(visibleW / 12, 0.42, 0.9));
        world.position.y = w >= 1024 ? 0 : visibleH * 0.3;
    }
    window.addEventListener('resize', resize);
    resize();

    const pointer = { x: 0, y: 0 };
    window.addEventListener('pointermove', (ev) => {
        pointer.x = (ev.clientX / window.innerWidth) * 2 - 1;
        pointer.y = (ev.clientY / window.innerHeight) * 2 - 1;
    }, { passive: true });

    /* ---------------------------------------------------------------- loop */
    const clock = new THREE.Clock();
    let spawnClock = 0;
    const target = new THREE.Vector3();

    function frame() {
        const dt = Math.min(clock.getDelta(), 0.05);
        const time = clock.elapsedTime;

        logo.rotation.y += dt * 0.55;
        logo.position.y = Math.sin(time * 0.9) * 0.12;
        logo.rotation.x = Math.sin(time * 0.6) * 0.06;
        net.rotation.y += dt * 0.035;
        ring.rotation.z += dt * 0.25;
        ring2.rotation.z -= dt * 0.12;
        ring.material.opacity += (0.55 - ring.material.opacity) * Math.min(1, dt * 3);
        core.intensity = 16 + Math.sin(time * 2.2) * 3;

        spawnClock += dt;
        const every = small ? 0.32 : 0.2;
        while (spawnClock > every) {
            spawnClock -= every;
            if (packets.length < (small ? 26 : 48)) spawnPacket();
        }

        for (let i = packets.length - 1; i >= 0; i--) {
            const p = packets[i];
            p.t += dt * p.speed;
            const stopAt = p.threat ? 1 - RING_R / p.from.length() : 0.98;
            const tt = Math.min(p.t, stopAt);
            p.mesh.position.copy(p.from).multiplyScalar(1 - tt);
            const fadeIn = Math.min(1, p.t * 6);
            p.mesh.material.opacity = fadeIn;
            const tail = Math.max(0, tt - 0.12);
            const pos = p.trail.geometry.attributes.position;
            pos.setXYZ(0, p.from.x * (1 - tail), p.from.y * (1 - tail), p.from.z * (1 - tail));
            pos.setXYZ(1, p.mesh.position.x, p.mesh.position.y, p.mesh.position.z);
            pos.needsUpdate = true;
            p.trail.material.opacity = 0.45 * fadeIn;
            if (p.t >= stopAt) {
                if (p.threat) burst(p.mesh.position);
                net.remove(p.mesh, p.trail);
                p.mesh.material.dispose();
                p.trail.geometry.dispose();
                p.trail.material.dispose();
                packets.splice(i, 1);
            }
        }

        for (let i = bursts.length - 1; i >= 0; i--) {
            const b = bursts[i];
            b.t += dt;
            b.m.scale.setScalar(1 + b.t * 9);
            b.m.material.opacity = Math.max(0, 0.9 - b.t * 1.8);
            if (b.t > 0.5) {
                net.remove(b.m);
                b.m.material.dispose();
                bursts.splice(i, 1);
            }
        }

        target.set(pointer.x * 1.2, 0.6 - pointer.y * 0.7, 16);
        camera.position.lerp(target, Math.min(1, dt * 1.5));
        camera.lookAt(0, 0, 0);

        renderer.render(scene, camera);
    }

    if (reduceMotion) {
        logo.rotation.y = 0.5;
        for (let i = 0; i < 18; i++) spawnPacket();
        packets.forEach((p) => { p.t = Math.random() * 0.6; });
        frame();
        window.addEventListener('resize', () => renderer.render(scene, camera));
    } else {
        renderer.setAnimationLoop(frame);
    }
    document.documentElement.classList.add('pfc-webgl-ready');
}
