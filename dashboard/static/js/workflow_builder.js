// ============================================================================
// CyberToolkit Pro — Visual Kill-Chain Blueprint Builder
// ============================================================================
// Drag-and-drop interactive node graph for constructing multi-stage cyber
// attack pipelines. Supports live execution, YAML profile generation,
// bezier connection routing, and full state persistence.
// ============================================================================

class WorkflowBuilder {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.nodes = [];
        this.links = [];
        this.nodeCounter = 0;

        this.isDragging = false;
        this.draggedNode = null;
        this.dragOffset = { x: 0, y: 0 };

        this.isLinking = false;
        this.linkStartNode = null;

        // Container positioning
        if (this.container) {
            this.container.style.position = 'relative';
            this.container.style.overflow = 'hidden';
            this.container.innerHTML = '';
        }

        // SVG Canvas for Bezier Link Cables
        this.svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        this.svg.style.position = 'absolute';
        this.svg.style.top = '0';
        this.svg.style.left = '0';
        this.svg.style.width = '100%';
        this.svg.style.height = '100%';
        this.svg.style.pointerEvents = 'none';
        this.svg.style.zIndex = '1';
        this.container.appendChild(this.svg);

        // Active connection line when dragging from output port
        this.activeLine = document.createElementNS("http://www.w3.org/2000/svg", "path");
        this.activeLine.setAttribute('stroke', '#00f0ff');
        this.activeLine.setAttribute('stroke-width', '3');
        this.activeLine.setAttribute('fill', 'none');
        this.activeLine.setAttribute('stroke-dasharray', '6,6');
        this.activeLine.style.display = 'none';
        this.svg.appendChild(this.activeLine);

        this.initEvents();
    }

    initEvents() {
        if (!this.container) return;

        this.container.addEventListener('mousemove', this.onMouseMove.bind(this));
        this.container.addEventListener('mouseup', this.onMouseUp.bind(this));
        this.container.addEventListener('mouseleave', this.onMouseUp.bind(this));

        // Right-click context menu
        this.container.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            const rect = this.container.getBoundingClientRect();
            this.showContextMenu(e.clientX - rect.left, e.clientY - rect.top);
        });

        // Window resize updates connection links
        window.addEventListener('resize', () => {
            this.updateLinks();
        });
    }

    addNode(type, name, toolPath = '', x = 100, y = 100) {
        this.nodeCounter++;
        const id = `wf_node_${this.nodeCounter}`;

        const el = document.createElement('div');
        el.className = `wf-node type-${type}`;
        el.id = id;
        el.style.left = `${x}px`;
        el.style.top = `${y}px`;

        let icon = '⚙️';
        let badge = type.toUpperCase();
        if (type === 'target') { icon = '🎯'; badge = 'TARGET'; }
        else if (type === 'scanner') { icon = '📡'; badge = 'SCANNER'; }
        else if (type === 'exploiter') { icon = '💣'; badge = 'EXPLOIT'; }
        else if (type === 'reporter') { icon = '📝'; badge = 'REPORT'; }

        el.innerHTML = `
            <div class="wf-header">
                <span>${icon} ${name}</span>
                <span style="font-size:0.65rem; font-family:'JetBrains Mono', monospace; opacity:0.8;">${badge}</span>
            </div>
            <div class="wf-body">
                <div class="wf-port wf-in" data-node="${id}" title="Input Stage"></div>
                <div style="font-size:0.75rem; color:var(--text-dim); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                    ${toolPath || 'Pipeline Input'}
                </div>
                <div class="wf-port wf-out" data-node="${id}" title="Connect to next stage"></div>
            </div>
            <button class="wf-delete" title="Delete stage" onclick="window.wf && window.wf.deleteNode('${id}')">✕</button>
        `;

        this.container.appendChild(el);

        const nodeObj = { id, el, type, name, toolPath, x, y };
        this.nodes.push(nodeObj);

        // Header Dragging
        const header = el.querySelector('.wf-header');
        header.addEventListener('mousedown', (e) => {
            if (e.target.closest('.wf-delete')) return;
            this.isDragging = true;
            this.draggedNode = nodeObj;
            this.dragOffset.x = e.clientX - el.getBoundingClientRect().left;
            this.dragOffset.y = e.clientY - el.getBoundingClientRect().top;
            el.style.zIndex = '25';
        });

        // Link Output Port
        const outPort = el.querySelector('.wf-out');
        outPort.addEventListener('mousedown', (e) => {
            e.stopPropagation();
            this.isLinking = true;
            this.linkStartNode = nodeObj;
            this.activeLine.style.display = 'block';
        });

        // Link Input Port
        const inPort = el.querySelector('.wf-in');
        inPort.addEventListener('mouseup', (e) => {
            e.stopPropagation();
            if (this.isLinking && this.linkStartNode && this.linkStartNode.id !== id) {
                this.addLink(this.linkStartNode.id, id);
                this.endLinking();
            }
        });

        this.updateLinks();
        return nodeObj;
    }

    addLink(sourceId, targetId) {
        // Prevent duplicates
        if (this.links.find(l => l.source === sourceId && l.target === targetId)) return;
        this.links.push({ source: sourceId, target: targetId });
        this.updateLinks();
    }

    deleteNode(id) {
        this.nodes = this.nodes.filter(n => n.id !== id);
        this.links = this.links.filter(l => l.source !== id && l.target !== id);
        const el = document.getElementById(id);
        if (el) el.remove();
        this.updateLinks();
    }

    clearCanvas() {
        this.nodes.forEach(n => {
            const el = document.getElementById(n.id);
            if (el) el.remove();
        });
        this.nodes = [];
        this.links = [];
        this.nodeCounter = 0;
        this.updateLinks();
    }

    loadDefaultKillChain() {
        this.clearCanvas();
        const n1 = this.addNode('target', 'Target Perimeter', '127.0.0.1 (Localhost)', 60, 160);
        const n2 = this.addNode('scanner', 'Port Scanner', 'scanning.port_scanner', 320, 160);
        const n3 = this.addNode('scanner', 'HTTP Fingerprint', 'reconnaissance.http_fingerprint', 580, 160);
        const n4 = this.addNode('reporter', 'JSON Report', 'reporting.json_report', 840, 160);

        this.addLink(n1.id, n2.id);
        this.addLink(n2.id, n3.id);
        this.addLink(n3.id, n4.id);
    }

    onMouseMove(e) {
        const rect = this.container.getBoundingClientRect();

        if (this.isDragging && this.draggedNode) {
            let x = e.clientX - rect.left - this.dragOffset.x;
            let y = e.clientY - rect.top - this.dragOffset.y;

            // Clamping
            x = Math.max(10, Math.min(rect.width - 230, x));
            y = Math.max(10, Math.min(rect.height - 110, y));

            this.draggedNode.x = x;
            this.draggedNode.y = y;
            this.draggedNode.el.style.left = `${x}px`;
            this.draggedNode.el.style.top = `${y}px`;
            this.updateLinks();
        }

        if (this.isLinking && this.linkStartNode) {
            const outPort = this.linkStartNode.el.querySelector('.wf-out');
            if (outPort) {
                const portRect = outPort.getBoundingClientRect();
                const startX = portRect.left - rect.left + portRect.width / 2;
                const startY = portRect.top - rect.top + portRect.height / 2;
                const endX = e.clientX - rect.left;
                const endY = e.clientY - rect.top;

                this.drawCurvedLine(this.activeLine, startX, startY, endX, endY);
            }
        }
    }

    endLinking() {
        this.isLinking = false;
        this.linkStartNode = null;
        this.activeLine.style.display = 'none';
        this.activeLine.setAttribute('d', '');
    }

    onMouseUp() {
        if (this.draggedNode) {
            this.draggedNode.el.style.zIndex = '10';
        }
        this.isDragging = false;
        this.draggedNode = null;
        this.endLinking();
    }

    updateLinks() {
        if (!this.container || !this.svg) return;

        // Clear existing solid links
        const paths = this.svg.querySelectorAll('path.solid-link');
        paths.forEach(p => p.remove());

        const rect = this.container.getBoundingClientRect();

        this.links.forEach(link => {
            const srcNode = this.nodes.find(n => n.id === link.source);
            const tgtNode = this.nodes.find(n => n.id === link.target);
            if (!srcNode || !tgtNode) return;

            const outPort = srcNode.el.querySelector('.wf-out');
            const inPort = tgtNode.el.querySelector('.wf-in');
            if (!outPort || !inPort) return;

            const outRect = outPort.getBoundingClientRect();
            const inRect = inPort.getBoundingClientRect();

            const startX = outRect.left - rect.left + outRect.width / 2;
            const startY = outRect.top - rect.top + outRect.height / 2;
            const endX = inRect.left - rect.left + inRect.width / 2;
            const endY = inRect.top - rect.top + inRect.height / 2;

            const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
            path.classList.add('solid-link');
            path.setAttribute('stroke', '#00f0ff');
            path.setAttribute('stroke-width', '3.5');
            path.setAttribute('fill', 'none');
            path.style.cursor = 'pointer';
            path.style.pointerEvents = 'stroke';
            path.setAttribute('title', 'Click to disconnect');

            this.drawCurvedLine(path, startX, startY, endX, endY);

            // Click link to remove
            path.addEventListener('click', () => {
                this.links = this.links.filter(l => l !== link);
                this.updateLinks();
            });

            this.svg.appendChild(path);
        });
    }

    drawCurvedLine(pathEl, startX, startY, endX, endY) {
        const dx = Math.abs(endX - startX);
        const offset = Math.max(dx * 0.45, 45);
        const d = `M ${startX} ${startY} C ${startX + offset} ${startY}, ${endX - offset} ${endY}, ${endX} ${endY}`;
        pathEl.setAttribute('d', d);
    }

    showContextMenu(x, y) {
        const existing = document.getElementById('wf-context-menu');
        if (existing) existing.remove();

        const menu = document.createElement('div');
        menu.id = 'wf-context-menu';
        menu.style.left = `${x}px`;
        menu.style.top = `${y}px`;

        const tools = [
            { type: 'target', label: 'Add Target Scope', path: 'target' },
            { type: 'scanner', label: 'Port Scanner', path: 'scanning.port_scanner' },
            { type: 'scanner', label: 'HTTP Fingerprint', path: 'reconnaissance.http_fingerprint' },
            { type: 'scanner', label: 'DNS Recon', path: 'reconnaissance.dns_lookup' },
            { type: 'exploiter', label: 'Vulnerability Audit', path: 'scanning.nse_runner' },
            { type: 'reporter', label: 'JSON Security Report', path: 'reporting.json_report' },
        ];

        menu.innerHTML = `
            <div style="font-size:0.7rem; font-weight:700; color:var(--cyan); padding:0.25rem 0.5rem; text-transform:uppercase;">
                Stage Arsenal
            </div>
            ${tools.map(t => `
                <div class="menu-item" data-type="${t.type}" data-label="${t.label}" data-path="${t.path}">
                    <span>${t.type === 'target' ? '🎯' : t.type === 'scanner' ? '📡' : t.type === 'exploiter' ? '💣' : '📝'}</span>
                    <span>${t.label}</span>
                </div>
            `).join('')}
        `;

        this.container.appendChild(menu);

        menu.querySelectorAll('.menu-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const target = e.currentTarget;
                const type = target.getAttribute('data-type');
                const label = target.getAttribute('data-label');
                const path = target.getAttribute('data-path');
                this.addNode(type, label, path, x, y);
                menu.remove();
            });
        });

        setTimeout(() => {
            window.addEventListener('click', () => {
                const el = document.getElementById('wf-context-menu');
                if (el) el.remove();
            }, { once: true });
        }, 20);
    }

    exportYaml() {
        // Collect execution order by link topology
        const steps = [];
        this.nodes.forEach(n => {
            if (n.toolPath && n.type !== 'target') {
                steps.push(n.toolPath);
            }
        });

        const yaml = [
            `# =============================================================================`,
            `# CyberToolkit Pro — Custom Kill-Chain Pipeline`,
            `# Generated: ${new Date().toISOString()}`,
            `# =============================================================================`,
            `name: "Custom Visual Kill-Chain"`,
            `description: "Automated multi-stage assessment built visually in CyberToolkit Pro"`,
            `steps:`,
            ...(steps.map(s => `  - ${s}`)),
            ``
        ].join('\n');

        return yaml;
    }

    async runKillChain(targetHost) {
        const steps = this.nodes
            .filter(n => n.toolPath && n.type !== 'target')
            .map(n => n.toolPath);

        if (steps.length === 0) {
            alert("No tool stages configured in the kill-chain graph! Add at least one scanner or report node.");
            return;
        }

        const target = targetHost || prompt("Enter target IP or domain for Kill-Chain execution:", "127.0.0.1");
        if (!target) return;

        // Open execution drawer to show live progress
        if (typeof switchTab === 'function') switchTab('explorer');

        document.getElementById('drawerToolTitle').textContent = `Kill-Chain: ${steps.length} Stages`;
        document.getElementById('drawerToolDesc').textContent = `Executing automated kill-chain pipeline against ${target}`;
        document.getElementById('drawerToolPath').textContent = steps.join(' → ');
        document.getElementById('drawerFormFields').innerHTML = '';
        document.getElementById('drawerLoading').classList.add('active');
        document.getElementById('drawerResults').classList.remove('active');
        document.getElementById('drawerBackdrop').classList.add('active');
        document.getElementById('runDrawer').classList.add('active');

        try {
            const resp = await fetch('/api/pipeline/adhoc', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ steps: steps, args: { target } })
            });
            const data = await resp.json();
            if (typeof showDrawerResults === 'function') {
                showDrawerResults(data);
            }
        } catch (e) {
            if (typeof showDrawerResults === 'function') {
                showDrawerResults({ status: 'error', error: e.message });
            }
        } finally {
            document.getElementById('drawerLoading').classList.remove('active');
        }
    }
}

// Global Singleton
window.wf = null;
