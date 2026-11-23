(() => {
  "use strict";

  const config = window.EAA_SITE || {};
  const byId = (id) => document.getElementById(id);
  const make = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  };

  const menuButton = document.querySelector(".nav-toggle");
  const menu = byId("eaa-primary-menu");
  if (menuButton && menu) {
    menuButton.addEventListener("click", () => {
      const expanded = menuButton.getAttribute("aria-expanded") === "true";
      menuButton.setAttribute("aria-expanded", expanded ? "false" : "true");
      menu.classList.toggle("is-open", !expanded);
    });
  }

  const formatPrice = (plan) => {
    const price = plan && plan.price;
    if (!price || !price.currency_code || price.amount_minor === undefined) {
      return "Price confirmed at secure checkout";
    }
    try {
      const currency = String(price.currency_code).toUpperCase();
      const minor = Number(price.amount_minor);
      if (!Number.isFinite(minor) || minor < 0 || !/^[A-Z]{3}$/.test(currency)) {
        throw new Error("Invalid catalogue price");
      }
      const formatter = new Intl.NumberFormat(undefined, { style: "currency", currency });
      const fractionDigits = formatter.resolvedOptions().maximumFractionDigits;
      const amount = formatter.format(minor / Math.pow(10, fractionDigits));
      if (!price.billing_cycle_interval) return amount + " one-time";
      const frequency = Math.max(1, Number(price.billing_cycle_frequency) || 1);
      const interval = String(price.billing_cycle_interval);
      return amount + " / " + (frequency === 1 ? interval : "every " + frequency + " " + interval + "s");
    } catch (_) {
      return "Price confirmed at secure checkout";
    }
  };

  const featureDefinitions = [
    ["standard_audits", "Standard ecommerce audits"],
    ["conversion_dossier", "Conversion Dossier"],
    ["white_label_branding", "White-label branding"],
    ["agency_management", "Agency / multiple client workspaces"],
    ["direct_api_access", "Direct API access"]
  ];

  const renderPlans = async () => {
    const plansNode = byId("eaa-plans");
    if (!plansNode) return;
    const status = byId("eaa-plans-status");
    const email = byId("eaa-checkout-email");
    const head = byId("eaa-compare-head");
    const body = byId("eaa-compare-body");
    const setStatus = (message) => { if (status) status.textContent = message; };

    try {
      if (!config.plansUrl) throw new Error("The package catalogue endpoint is not configured.");
      const response = await fetch(config.plansUrl, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !Array.isArray(data.plans)) {
        throw new Error(data.message || "The live package catalogue is temporarily unavailable.");
      }

      const order = ["starter", "pro", "business"];
      const plans = data.plans
        .filter((plan) => order.includes(String(plan.tier || "").toLowerCase()))
        .sort((a, b) => order.indexOf(String(a.tier).toLowerCase()) - order.indexOf(String(b.tier).toLowerCase()));
      if (!plans.length) throw new Error("No supported packages are currently available.");

      plansNode.replaceChildren();
      plans.forEach((plan) => {
        const tier = String(plan.tier || "").toLowerCase();
        const card = make("article", undefined, "plan-card" + (tier === "pro" ? " is-featured" : ""));
        card.append(make("h3", plan.label || tier.charAt(0).toUpperCase() + tier.slice(1)));
        const audience = tier === "starter" ? "For individual store owners" : (tier === "pro" ? "For growing ecommerce teams" : "For agencies managing client workspaces");
        card.append(make("p", audience, "plan-tag"));
        card.append(make("div", formatPrice(plan), "plan-price"));

        const allowance = Number(plan.monthly_audit_allowance);
        card.append(make("div", Number.isFinite(allowance) ? allowance.toLocaleString() : "Catalogue-defined", "plan-quota"));
        const concurrency = Number(plan.max_concurrent_audits);
        card.append(make("div", "audits per month · " + (Number.isFinite(concurrency) ? concurrency : "Catalogue-defined") + " concurrent", "plan-sub"));

        const list = make("ul", undefined, "plan-features");
        featureDefinitions.forEach(([key, label]) => {
          if (plan.features && plan.features[key] === true) list.append(make("li", label));
        });
        card.append(list);

        const button = make("button", "Continue to secure checkout", "button" + (tier === "pro" ? "" : " button-secondary"));
        button.type = "button";
        button.addEventListener("click", () => {
          const accountEmail = email ? email.value.trim() : "";
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(accountEmail) || accountEmail.length > 254) {
            setStatus("Enter a valid customer account email before checkout.");
            if (email) email.focus();
            return;
          }
          const form = document.createElement("form");
          form.method = "post";
          form.action = config.checkoutAction || "";
          const fields = {
            action: "eaa_checkout",
            _wpnonce: config.checkoutNonce || "",
            tier,
            email: accountEmail
          };
          Object.keys(fields).forEach((name) => {
            const input = document.createElement("input");
            input.type = "hidden";
            input.name = name;
            input.value = fields[name];
            form.append(input);
          });
          document.body.append(form);
          button.disabled = true;
          setStatus("Preparing secure checkout…");
          form.submit();
        });
        card.append(button);
        plansNode.append(card);
      });

      if (head && body) {
        head.replaceChildren();
        body.replaceChildren();
        const headerRow = make("tr");
        headerRow.append(make("th", "Capability"));
        plans.forEach((plan) => headerRow.append(make("th", plan.label || plan.tier)));
        head.append(headerRow);

        const rows = [
          ["Price", (plan) => formatPrice(plan)],
          ["Monthly audit allowance", (plan) => {
            const value = Number(plan.monthly_audit_allowance);
            return Number.isFinite(value) ? value.toLocaleString() : "—";
          }],
          ["Concurrent audits", (plan) => {
            const value = Number(plan.max_concurrent_audits);
            return Number.isFinite(value) ? String(value) : "—";
          }],
          ...featureDefinitions.map(([key, label]) => [label, (plan) => plan.features && plan.features[key] === true ? "Included" : "—"])
        ];
        rows.forEach(([label, valueForPlan]) => {
          const row = make("tr");
          row.append(make("td", label));
          plans.forEach((plan) => {
            const value = valueForPlan(plan);
            const cell = make("td", value);
            if (value === "Included") cell.className = "yes";
            if (value === "—") cell.className = "no";
            row.append(cell);
          });
          body.append(row);
        });
      }
      setStatus("Package limits and entitlements loaded from the active operator-managed catalogue. Paddle confirms the final amount before payment.");
    } catch (error) {
      plansNode.replaceChildren(make("article", error.message || "The package catalogue could not be loaded.", "plan-card"));
      setStatus(error.message || "The package catalogue could not be loaded.");
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderPlans);
  } else {
    renderPlans();
  }
})();
