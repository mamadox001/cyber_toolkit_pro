// ============================================================================
// CyberToolkit Pro — 3D Attack Surface Visualizer (WebGL / Three.js)
// ============================================================================
// Provides a real-time, interactive 3D attack surface map rendering target nodes,
// network topology links, live packet traffic lasers, and detailed HUD telemetry.
// Supports mouse orbit/drag, wheel zoom, node raycasting, and Canvas 2D fallback.
// ============================================================================

class NetworkMap3D {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.raycaster = null;
        this.mouse = null;
        this.nodes = [];
        this.links = [];
        this.particles = [];
        this.animationId = null;
        this.trafficInterval = null;
        this.initialized = false;
        this.isFallback2D = false;

        // Camera Orbit Controls State
        this.isMouseDown = false;
        this.prevMousePos = { x: 0, y: 0 };
        this.theta = 0.5;      // azimuthal angle
        this.phi = 0.45;       // polar angle
        this.radius = 420;     // camera distance
        this.autoRotate = true;
        this.hoveredNode = null;
        this.tooltipEl = null;
    }

    init() {
        if (this.initialized) {
            this.onWindowResize();
            return;
        }

        if (!this.container) return;
        this.container.innerHTML = '';

        // Inject Tooltip DOM
        this.tooltipEl = document.createElement('div');
        this.tooltipEl.className = 'map-3d-tooltip';
        this.tooltipEl.style.cssText = `
            position: absolute; display: none; z-index: 50;
            background: rgba(6, 12, 28, 0.94); border: 1px solid #00f0ff;
            border-radius: 8px; padding: 0.65rem 0.9rem; pointer-events: auto;
            box-shadow: 0 0 20px rgba(0,240,255,0.3); font-family: 'Outfit', sans-serif;
            font-size: 0.8rem; color: #f1f5f9; backdrop-filter: blur(12px);
        `;
        this.container.style.position = 'relative';
        this.container.appendChild(this.tooltipEl);

        // Check Three.js availability
        if (typeof THREE === 'undefined') {
            console.warn("[3D Map] Three.js not found, switching to High-Performance 2D Canvas Topology");
            this.init2DFallback();
            return;
        }

        try {
            const width = this.container.clientWidth || window.innerWidth;
            const height = this.container.clientHeight || (window.innerHeight - 72);

            // Setup Scene & Fog
            this.scene = new THREE.Scene();
            this.scene.fog = new THREE.FogExp2(0x060913, 0.0018);

            // Setup Camera
            this.camera = new THREE.PerspectiveCamera(60, width / height, 1, 3000);
            this.updateCameraPos();

            // Setup WebGL Renderer
            this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
            this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
            this.renderer.setSize(width, height);
            this.renderer.setClearColor(0x060913, 1);
            this.container.appendChild(this.renderer.domElement);

            // Interactive Raycaster
            this.raycaster = new THREE.Raycaster();
            this.mouse = new THREE.Vector2(-999, -999);

            // Ambient & Point Lighting
            const ambientLight = new THREE.AmbientLight(0x38bdf8, 0.6);
            this.scene.add(ambientLight);

            const centerLight = new THREE.PointLight(0x00f0ff, 2.5, 800);
            centerLight.position.set(0, 50, 0);
            this.scene.add(centerLight);

            // Cyberpunk Grid Matrix
            const grid = new THREE.GridHelper(1200, 48, 0x00f0ff, 0x141f38);
            grid.position.y = -110;
            grid.material.opacity = 0.35;
            grid.material.transparent = true;
            this.scene.add(grid);

            // Central Node: CyberToolkit Core Server
            this.createNode(0, 0, 0, 0x00f0ff, "CyberToolkit Server", 16, { type: 'core', ip: '127.0.0.1 (Local Engine)' });

            // Setup Event Handlers
            this.initInteractionEvents();

            this.initialized = true;
            this.animate();
            this.fetchTargets();

            // Packet Traffic Simulation
            this.trafficInterval = setInterval(() => this.shootPacket(), 380);

        } catch (err) {
            console.error("[3D Map] WebGL initialization failed:", err);
            this.init2DFallback();
        }
    }

    updateCameraPos() {
        this.camera.position.x = this.radius * Math.sin(this.phi) * Math.cos(this.theta);
        this.camera.position.y = this.radius * Math.cos(this.phi);
        this.camera.position.z = this.radius * Math.sin(this.phi) * Math.sin(this.theta);
        this.camera.lookAt(0, 0, 0);
    }

    initInteractionEvents() {
        const dom = this.renderer.domElement;

        // Mouse Drag to Orbit
        dom.addEventListener('mousedown', (e) => {
            this.isMouseDown = true;
            this.autoRotate = false;
            this.prevMousePos = { x: e.clientX, y: e.clientY };
        });

        window.addEventListener('mouseup', () => {
            this.isMouseDown = false;
        });

        dom.addEventListener('mousemove', (e) => {
            const rect = dom.getBoundingClientRect();
            this.mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
            this.mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

            if (this.isMouseDown) {
                const deltaX = e.clientX - this.prevMousePos.x;
                const deltaY = e.clientY - this.prevMousePos.y;
                this.theta -= deltaX * 0.006;
                this.phi = Math.max(0.15, Math.min(Math.PI / 2 - 0.05, this.phi - deltaY * 0.006));
                this.prevMousePos = { x: e.clientX, y: e.clientY };
                this.updateCameraPos();
            }

            this.checkRaycast(e.clientX, e.clientY, rect);
        });

        // Mouse Wheel to Zoom
        dom.addEventListener('wheel', (e) => {
            e.preventDefault();
            this.radius = Math.max(160, Math.min(900, this.radius + e.deltaY * 0.45));
            this.updateCameraPos();
        }, { passive: false });

        // Double Click to Reset View
        dom.addEventListener('dblclick', () => {
            this.radius = 420;
            this.phi = 0.45;
            this.theta = 0.5;
            this.autoRotate = true;
            this.updateCameraPos();
        });

        window.addEventListener('resize', this.onWindowResize.bind(this));
    }

    checkRaycast(clientX, clientY, rect) {
        if (!this.raycaster || !this.camera || this.nodes.length === 0) return;

        this.raycaster.setFromCamera(this.mouse, this.camera);
        const meshes = this.nodes.map(n => n.mesh);
        const intersects = this.raycaster.intersectObjects(meshes);

        if (intersects.length > 0) {
            const hitMesh = intersects[0].object;
            const nodeData = this.nodes.find(n => n.mesh === hitMesh);
            if (nodeData) {
                this.hoveredNode = nodeData;
                this.showTooltip(clientX - rect.left, clientY - rect.top, nodeData);
                document.body.style.cursor = 'pointer';
                return;
            }
        }

        this.hoveredNode = null;
        this.hideTooltip();
        document.body.style.cursor = 'default';
    }

    showTooltip(x, y, node) {
        if (!this.tooltipEl) return;
        const meta = node.meta || {};
        this.tooltipEl.style.display = 'block';
        this.tooltipEl.style.left = `${Math.min(x + 14, (this.container.clientWidth || 800) - 220)}px`;
        this.tooltipEl.style.top = `${Math.max(10, y - 20)}px`;

        this.tooltipEl.innerHTML = `
            <div style="font-weight:700; color:var(--cyan); margin-bottom:0.3rem; display:flex; align-items:center; gap:0.4rem;">
                <span>🎯</span> ${node.label}
            </div>
            <div style="font-size:0.75rem; color:#94a3b8; margin-bottom:0.2rem;">Type: <b style="color:#fff;">${meta.type || 'Host'}</b></div>
            ${meta.ip ? `<div style="font-size:0.75rem; color:#94a3b8; margin-bottom:0.2rem;">IP: <b style="color:var(--emerald);">${meta.ip}</b></div>` : ''}
            <div style="font-size:0.75rem; color:#94a3b8; margin-bottom:0.45rem;">
                Findings: <b style="color:${(meta.total_findings || 0) > 0 ? 'var(--crimson)' : 'var(--emerald)'};">${meta.total_findings || 0}</b>
            </div>
            <button onclick="window.map3d && window.map3d.quickScanTarget('${node.label}')" style="
                background: linear-gradient(135deg, #00f0ff, #0284c7); border: none; border-radius: 4px;
                color: #060913; font-weight: 700; font-size: 0.72rem; padding: 0.25rem 0.6rem; cursor: pointer;
            ">▶ Quick Scan</button>
        `;
    }

    hideTooltip() {
        if (this.tooltipEl) this.tooltipEl.style.display = 'none';
    }

    quickScanTarget(target) {
        if (typeof openToolDrawer === 'function') {
            openToolDrawer('scanning.port_scanner');
            const targetInput = document.getElementById('field_target');
            if (targetInput) targetInput.value = target;
        }
    }

    createNode(x, y, z, colorHex, label, size = 10, meta = {}) {
        const geometry = new THREE.SphereGeometry(size, 16, 16);
        const material = new THREE.MeshBasicMaterial({
            color: colorHex,
            wireframe: true,
            transparent: true,
            opacity: 0.85
        });
        const sphere = new THREE.Mesh(geometry, material);
        sphere.position.set(x, y, z);
        this.scene.add(sphere);

        // Ambient inner core glow
        const innerGeo = new THREE.SphereGeometry(size * 0.5, 12, 12);
        const innerMat = new THREE.MeshBasicMaterial({ color: colorHex });
        const inner = new THREE.Mesh(innerGeo, innerMat);
        sphere.add(inner);

        // Exterior aura glow
        const glowGeo = new THREE.SphereGeometry(size * 1.6, 14, 14);
        const glowMat = new THREE.MeshBasicMaterial({
            color: colorHex,
            transparent: true,
            opacity: 0.18,
            wireframe: false
        });
        const glow = new THREE.Mesh(glowGeo, glowMat);
        sphere.add(glow);

        const nodeData = { mesh: sphere, x, y, z, label, meta, size };
        this.nodes.push(nodeData);
        return nodeData;
    }

    createLink(nodeA, nodeB, colorHex = 0x00f0ff) {
        const material = new THREE.LineBasicMaterial({
            color: colorHex,
            transparent: true,
            opacity: 0.35,
            linewidth: 1
        });
        const points = [
            new THREE.Vector3(nodeA.x, nodeA.y, nodeA.z),
            new THREE.Vector3(nodeB.x, nodeB.y, nodeB.z)
        ];
        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        const line = new THREE.Line(geometry, material);
        this.scene.add(line);
        this.links.push({ nodeA, nodeB, line });
        return { nodeA, nodeB, line };
    }

    shootPacket() {
        if (this.nodes.length < 2 || !this.scene) return;
        const source = this.nodes[0];
        const target = this.nodes[Math.floor(Math.random() * (this.nodes.length - 1)) + 1];

        const geometry = new THREE.SphereGeometry(2.5, 8, 8);
        const colors = [0x00f0ff, 0xa855f7, 0x10b981, 0xff0055];
        const packetColor = colors[Math.floor(Math.random() * colors.length)];
        const material = new THREE.MeshBasicMaterial({ color: packetColor });
        const mesh = new THREE.Mesh(geometry, material);

        mesh.position.copy(source.mesh.position);
        this.scene.add(mesh);

        this.particles.push({
            mesh: mesh,
            start: source.mesh.position.clone(),
            end: target.mesh.position.clone(),
            progress: 0,
            speed: 0.016 + Math.random() * 0.02
        });
    }

    async fetchTargets() {
        try {
            const resp = await fetch('/api/targets');
            let targets = [];
            if (resp.ok) {
                const data = await resp.json();
                targets = data.targets || [];
            }

            // If empty, generate rich cyber reconnaissance demo topology
            if (targets.length === 0) {
                targets = [
                    { target: '192.168.1.1', target_type: 'gateway', scan_count: 5, total_findings: 1 },
                    { target: '10.0.0.15', target_type: 'dmz_firewall', scan_count: 3, total_findings: 0 },
                    { target: 'api.production.internal', target_type: 'domain', scan_count: 8, total_findings: 4 },
                    { target: 'auth.auth0-corp.net', target_type: 'domain', scan_count: 2, total_findings: 2 },
                    { target: 'db-cluster-primary.lan', target_type: 'ip', scan_count: 12, total_findings: 3 },
                    { target: 's3-backup-vault', target_type: 'cloud', scan_count: 4, total_findings: 0 },
                    { target: 'workstation-dev-01', target_type: 'endpoint', scan_count: 1, total_findings: 5 }
                ];
            }

            const radius = 220;
            targets.forEach((t, i) => {
                const targetName = (typeof t === 'object' && t !== null) ? (t.target || 'Target') : String(t);
                const angle = (i / targets.length) * Math.PI * 2;
                const dist = radius + (i % 2 === 0 ? 30 : -25);
                const x = Math.cos(angle) * dist;
                const z = Math.sin(angle) * dist;
                const y = ((i % 3) - 1) * 45;

                let color = 0x00f0ff;
                if (t.target_type === 'gateway' || targetName.includes('192.168')) color = 0x10b981;
                else if (t.total_findings > 2) color = 0xff0055;
                else if (t.target_type === 'domain') color = 0xa855f7;

                const node = this.createNode(x, y, z, color, targetName, 9, {
                    type: t.target_type || 'Host',
                    ip: t.target || targetName,
                    total_findings: t.total_findings || 0
                });
                this.createLink(this.nodes[0], node, color);
            });

        } catch (e) {
            console.warn("[3D Map] Target loading fallback to internal nodes", e);
        }
    }

    onWindowResize() {
        if (!this.container) return;
        const width = this.container.clientWidth || window.innerWidth;
        const height = this.container.clientHeight || (window.innerHeight - 72);

        if (this.camera && this.renderer) {
            this.camera.aspect = width / height;
            this.camera.updateProjectionMatrix();
            this.renderer.setSize(width, height);
        }

        if (this.isFallback2D && this.canvas2D) {
            this.canvas2D.width = width;
            this.canvas2D.height = height;
        }
    }

    animate() {
        this.animationId = requestAnimationFrame(this.animate.bind(this));

        // Auto subtle orbital rotation if user is not actively dragging
        if (this.autoRotate) {
            this.theta += 0.0025;
            this.updateCameraPos();
        }

        // Rotate individual nodes
        this.nodes.forEach(n => {
            n.mesh.rotation.y += 0.012;
            n.mesh.rotation.x += 0.006;
        });

        // Animate packet lasers
        for (let i = this.particles.length - 1; i >= 0; i--) {
            const p = this.particles[i];
            p.progress += p.speed;
            if (p.progress >= 1) {
                this.scene.remove(p.mesh);
                this.particles.splice(i, 1);
            } else {
                p.mesh.position.lerpVectors(p.start, p.end, p.progress);
            }
        }

        this.renderer.render(this.scene, this.camera);
    }

    // High-Performance 2D Canvas Fallback
    init2DFallback() {
        this.isFallback2D = true;
        const canvas = document.createElement('canvas');
        this.canvas2D = canvas;
        const width = canvas.width = this.container.clientWidth || window.innerWidth;
        const height = canvas.height = this.container.clientHeight || (window.innerHeight - 72);
        this.container.appendChild(canvas);
        const ctx = canvas.getContext('2d');

        const nodes = [
            { x: width / 2, y: height / 2, r: 18, label: 'CyberToolkit Engine', color: '#00f0ff' },
            { x: width / 2 - 180, y: height / 2 - 90, r: 11, label: 'Gateway 192.168.1.1', color: '#10b981' },
            { x: width / 2 + 190, y: height / 2 - 100, r: 11, label: 'API Server', color: '#a855f7' },
            { x: width / 2 - 170, y: height / 2 + 110, r: 11, label: 'Auth Subsystem', color: '#00f0ff' },
            { x: width / 2 + 180, y: height / 2 + 100, r: 11, label: 'DB Cluster', color: '#ff0055' },
        ];

        let angle = 0;
        const render2D = () => {
            ctx.clearRect(0, 0, width, height);
            angle += 0.01;

            // Concentric rings
            ctx.strokeStyle = 'rgba(0, 240, 255, 0.1)';
            ctx.beginPath(); ctx.arc(width / 2, height / 2, 130, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath(); ctx.arc(width / 2, height / 2, 230, 0, Math.PI * 2); ctx.stroke();

            // Connect links
            nodes.slice(1).forEach(n => {
                ctx.strokeStyle = 'rgba(0, 240, 255, 0.25)';
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.moveTo(nodes[0].x, nodes[0].y);
                ctx.lineTo(n.x, n.y);
                ctx.stroke();
            });

            // Draw nodes
            nodes.forEach((n, idx) => {
                ctx.fillStyle = n.color;
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
                ctx.fill();

                // Glow
                ctx.strokeStyle = n.color;
                ctx.lineWidth = 2;
                ctx.stroke();

                // Text
                ctx.fillStyle = '#fff';
                ctx.font = '11px Outfit, sans-serif';
                ctx.fillText(n.label, n.x - 35, n.y + n.r + 14);
            });

            requestAnimationFrame(render2D);
        };
        render2D();
    }
}

// Global Singleton
window.map3d = null;
